use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use google_cloud_auth::credentials::{AccessTokenCredentials, Credentials};
use google_cloud_gax::retry_policy::NeverRetry;
use google_cloud_sql_v1::client::SqlConnectService;
use google_cloud_sql_v1::model::dns_name_mapping::ConnectionType;
use google_cloud_sql_v1::model::{SqlBackendType, SqlIpAddressType};
use rsa::pkcs8::EncodePrivateKey;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::verify_server_cert_signed_by_trust_anchor;
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use spki::EncodePublicKey;
use spki::der::pem::LineEnding;
use tokio::sync::OnceCell;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;

use crate::refresh::{Addr, BoxFuture, ConnectionInfo, Fetch};
use crate::{Error, InstanceConnectionName, IpType};

/// An RSA-2048 key pair. One key per process is used for all ephemeral certificates,
/// same as `getDefaultKeys` in the Go connector.
pub(crate) struct ClientKey {
    private_key: PrivatePkcs8KeyDer<'static>,
    public_key_pem: String,
}

impl ClientKey {
    /// Returns the key of the process.
    ///
    /// Async because the first call generates the RSA key in `spawn_blocking`, so the slow key
    /// generation does not block a runtime thread. A failed generation is not cached; the next
    /// call tries again.
    pub(crate) async fn shared() -> Result<Arc<Self>, Error> {
        CLIENT_KEY
            .get_or_try_init(|| async {
                tokio::task::spawn_blocking(Self::generate)
                    .await
                    .map_err(Error::key)?
                    .map(Arc::new)
            })
            .await
            .cloned()
    }

    fn generate() -> Result<Self, Error> {
        let key = rsa::PrivateKey::new(&mut rand::rng(), 2048).map_err(Error::key)?;
        let private_key = key.to_pkcs8_der().map_err(Error::key)?;
        let public_key_pem = key
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .map_err(Error::key)?;

        Ok(Self {
            private_key: PrivatePkcs8KeyDer::from(private_key.as_bytes().to_vec()),
            public_key_pem,
        })
    }
}

/// Gets connection info from the Cloud SQL Admin API. Port of `refresh.go` in the Go
/// connector.
pub(crate) struct AdminFetch {
    client: SqlConnectService,
    key: Arc<ClientKey>,
    provider: Arc<CryptoProvider>,
    /// The credentials for the IAM login token, if IAM authentication is enabled.
    iam_login: Option<AccessTokenCredentials>,
}

impl AdminFetch {
    pub(crate) async fn new(
        endpoint: &str,
        credentials: Credentials,
        provider: Arc<CryptoProvider>,
        iam_login: Option<AccessTokenCredentials>,
    ) -> Result<Self, Error> {
        // `retry_5xx` retries; the default client policy skips HTTP 500 and POST calls.
        let client = async {
            SqlConnectService::builder()
                .with_endpoint(endpoint)
                .with_credentials(credentials)
                .with_retry_policy(NeverRetry)
                .build()
                .await
                .map_err(|e| Error::api(e, false))
        };
        let (client, key) = tokio::try_join!(client, ClientKey::shared())?;

        Ok(Self {
            client,
            key,
            provider,
            iam_login,
        })
    }

    async fn fetch_inner(&self, name: &InstanceConnectionName) -> Result<ConnectionInfo, Error> {
        let (settings, cert) =
            tokio::try_join!(self.connect_settings(name), self.ephemeral_cert(name))?;

        let roots =
            server_ca_roots(&settings.server_ca_pem).map_err(|e| Error::certificate(name, e))?;
        let verifier = CloudSqlVerifier {
            roots,
            provider: self.provider.clone(),
            dns_names: settings.dns_names.values().cloned().collect(),
            legacy_common_name: name.legacy_common_name(),
        };
        let tls_config = client_config(
            self.provider.clone(),
            verifier,
            vec![cert.cert],
            PrivateKeyDer::Pkcs8(self.key.private_key.clone_key()),
        )
        .map_err(|e| Error::certificate(name, e))?;

        let mut addrs = HashMap::new();
        for (ip_type, host) in settings.addrs {
            // The TLS server name is the DNS name of the instance for the IP type, else the host.
            let server = settings.dns_names.get(&ip_type).unwrap_or(&host);
            let server_name =
                ServerName::try_from(server.clone()).map_err(|e| Error::certificate(name, e))?;
            addrs.insert(ip_type, Addr { host, server_name });
        }

        Ok(ConnectionInfo {
            addrs,
            database_version: settings.database_version,
            tls_config: Arc::new(tls_config),
            expiry: cert.expiry,
            login_token: cert.login_token,
        })
    }

    async fn connect_settings(&self, name: &InstanceConnectionName) -> Result<Settings, Error> {
        let settings = retry_5xx(|| {
            self.client
                .get_connect_settings()
                .set_project(name.project())
                .set_instance(name.name())
                .send()
        })
        .await?;

        if settings.region != name.region() {
            return Err(Error::Config(format!(
                "the region of instance {name} is {:?}, not {:?}",
                settings.region,
                name.region()
            )));
        }

        if settings.backend_type != SqlBackendType::SecondGen {
            return Err(Error::Config(format!(
                "instance {name} is not a second generation instance"
            )));
        }

        let mut addrs = HashMap::new();
        for mapping in settings.ip_addresses {
            let ip_type = match mapping.r#type {
                SqlIpAddressType::Primary => IpType::Public,
                SqlIpAddressType::Private => IpType::Private,
                _ => continue,
            };
            addrs.insert(ip_type, mapping.ip_address);
        }

        // Same as Go: take the DNS name of each connection type from `dnsNames`. Older
        // instances have only `dnsName`, which is used for the types without a name.
        let mut dns_names = HashMap::new();
        for mapping in &settings.dns_names {
            let ip_type = match mapping.connection_type {
                ConnectionType::Public => IpType::Public,
                ConnectionType::PrivateServicesAccess => IpType::Private,
                ConnectionType::PrivateServiceConnect => IpType::Psc,
                _ => continue,
            };
            if let Some(dns_name) = dns_name(&mapping.name) {
                dns_names.entry(ip_type).or_insert(dns_name);
            }
        }
        if let Some(legacy) = dns_name(&settings.dns_name) {
            for ip_type in [IpType::Public, IpType::Private, IpType::Psc] {
                dns_names.entry(ip_type).or_insert_with(|| legacy.clone());
            }
        }

        // A PSC instance has no IP address in the settings. Connect to its DNS name.
        if settings.psc_enabled
            && let Some(dns_name) = dns_names.get(&IpType::Psc)
        {
            addrs.insert(IpType::Psc, dns_name.clone());
        }

        let server_ca_pem = settings
            .server_ca_cert
            .map(|cert| cert.cert)
            .filter(|pem| !pem.is_empty())
            .ok_or_else(|| {
                Error::Config(format!("instance {name} has no server CA certificate"))
            })?;

        Ok(Settings {
            addrs,
            dns_names,
            database_version: settings.database_version.to_string(),
            server_ca_pem,
        })
    }

    async fn ephemeral_cert(&self, name: &InstanceConnectionName) -> Result<EphemeralCert, Error> {
        let access_token = match &self.iam_login {
            Some(credentials) => Some(credentials.access_token().await.map_err(Error::auth)?.token),
            None => None,
        };

        let response = retry_5xx(|| {
            let mut request = self
                .client
                .generate_ephemeral_cert()
                .set_project(name.project())
                .set_instance(name.name())
                .set_public_key(self.key.public_key_pem.clone());
            if let Some(token) = &access_token {
                request = request.set_access_token(token.clone());
            }
            request.send()
        })
        .await?;

        let pem = response
            .ephemeral_cert
            .map(|cert| cert.cert)
            .ok_or_else(|| Error::api(MissingField("ephemeral_cert"), true))?;
        let cert = CertificateDer::from_pem_slice(pem.as_bytes())
            .map_err(|e| Error::certificate(name, e))?;
        let expiry = not_after(&cert).map_err(|e| Error::certificate(name, e))?;

        Ok(EphemeralCert {
            cert,
            expiry,
            login_token: access_token.as_deref().map(token_hash),
        })
    }
}

impl Fetch for AdminFetch {
    fn fetch<'a>(
        &'a self,
        name: &'a InstanceConnectionName,
    ) -> BoxFuture<'a, Result<ConnectionInfo, Error>> {
        Box::pin(self.fetch_inner(name))
    }

    fn login_token_changed<'a>(&'a self, info: &'a ConnectionInfo) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            let Some(credentials) = &self.iam_login else {
                return false;
            };
            // The cache of google-cloud-auth answers this without a network call.
            match credentials.access_token().await {
                Ok(token) => Some(token_hash(&token.token)) != info.login_token,
                Err(error) => {
                    tracing::debug!(%error, "failed to get the IAM login token");
                    false
                }
            }
        })
    }
}

/// Identifies an IAM login token without keeping the token in the cache.
fn token_hash(token: &str) -> u64 {
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    token.hash(&mut hasher);
    hasher.finish()
}

struct Settings {
    addrs: HashMap<IpType, String>,
    dns_names: HashMap<IpType, String>,
    database_version: String,
    server_ca_pem: String,
}

struct EphemeralCert {
    cert: CertificateDer<'static>,
    expiry: SystemTime,
    login_token: Option<u64>,
}

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Debug, thiserror::Error)]
#[error("the response has no {0} field")]
struct MissingField(&'static str);

/// Retries HTTP 5xx, IO and timeout errors up to [`MAX_ATTEMPTS`] times, same as
/// `retry50x` in the Go connector.
async fn retry_5xx<T, F, Fut>(mut send: F) -> Result<T, Error>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = google_cloud_sql_v1::Result<T>>,
{
    let mut attempt = 0;
    loop {
        let error = match send().await {
            Ok(value) => return Ok(value),
            Err(error) => error,
        };

        // The client could not get an access token from the credentials.
        if error.is_authentication() {
            return Err(Error::auth(error));
        }

        let retryable = is_retryable(&error);
        attempt += 1;
        if !retryable || attempt >= MAX_ATTEMPTS {
            return Err(Error::api(error, retryable));
        }

        tokio::time::sleep(backoff(attempt)).await;
    }
}

fn is_retryable(error: &google_cloud_gax::error::Error) -> bool {
    error
        .http_status_code()
        .is_some_and(|code| (500..600).contains(&code))
        || error.is_io()
        || error.is_timeout()
        || error.is_connect()
}

/// Same as `exponentialBackoff` in the Go connector, without the jitter:
/// 200 ms, then multiplied by 1.618 for each attempt.
fn backoff(attempt: u32) -> Duration {
    Duration::from_millis(200).mul_f64(1.618_f64.powi(attempt as i32 - 1))
}

/// Returns the DNS name without the trailing dot, or `None` if it is empty.
fn dns_name(name: &str) -> Option<String> {
    Some(name.trim_end_matches('.').to_owned()).filter(|name| !name.is_empty())
}

fn server_ca_roots(pem: &str) -> Result<RootCertStore, BoxError> {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
        roots.add(cert?)?;
    }

    if roots.is_empty() {
        return Err("the server CA certificate is empty".into());
    }
    Ok(roots)
}

fn not_after(cert: &CertificateDer<'_>) -> Result<SystemTime, BoxError> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert)?;
    let seconds = u64::try_from(cert.validity().not_after.timestamp())
        .map_err(|_| "the ephemeral certificate expires before 1970")?;
    Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(seconds))
}

/// Verifies the server certificate, same as `tls_verify.go` in the Go connector: a valid
/// chain, and a SAN that matches a DNS name of the instance or the CN `project:instance`.
#[derive(Debug)]
struct CloudSqlVerifier {
    roots: RootCertStore,
    provider: Arc<CryptoProvider>,
    dns_names: Vec<String>,
    legacy_common_name: String,
}

impl ServerCertVerifier for CloudSqlVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        verify_server_cert_signed_by_trust_anchor(
            &ParsedCertificate::try_from(end_entity)?,
            &self.roots,
            intermediates,
            now,
            self.provider.signature_verification_algorithms.all,
        )?;

        let (_, cert) = x509_parser::parse_x509_certificate(end_entity)
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;

        // Compare by hand: the SANs end with a dot, and webpki does not match such names.
        let dns_name_matches = dns_sans(&cert).any(|presented| {
            let presented = presented.trim_end_matches('.');
            self.dns_names
                .iter()
                .any(|expected| expected.eq_ignore_ascii_case(presented))
        });
        if dns_name_matches {
            return Ok(ServerCertVerified::assertion());
        }

        let common_name = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok());
        if common_name == Some(self.legacy_common_name.as_str()) {
            return Ok(ServerCertVerified::assertion());
        }

        tracing::debug!(
            expected_dns_names = ?self.dns_names,
            expected_common_name = %self.legacy_common_name,
            presented_dns_names = ?dns_sans(&cert).collect::<Vec<_>>(),
            presented_common_name = ?common_name,
            "Cloud SQL server certificate is not valid for the instance"
        );
        Err(rustls::Error::InvalidCertificate(
            CertificateError::NotValidForName,
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Returns the DNS names in the subject alternative names of `cert`.
fn dns_sans<'a>(cert: &'a X509Certificate<'_>) -> impl Iterator<Item = &'a str> {
    cert.subject_alternative_name()
        .ok()
        .flatten()
        .into_iter()
        .flat_map(|san| san.value.general_names.iter())
        .filter_map(|name| match name {
            GeneralName::DNSName(name) => Some(*name),
            _ => None,
        })
}

/// Returns the rustls `CryptoProvider` that the application installed.
pub(crate) fn installed_provider() -> Result<Arc<CryptoProvider>, Error> {
    CryptoProvider::get_default().cloned().ok_or_else(|| {
        Error::Config(
            "no rustls CryptoProvider is installed: call \
             rustls::crypto::CryptoProvider::install_default() first"
                .into(),
        )
    })
}

/// Builds the TLS 1.3 client configuration with the ephemeral client certificate.
fn client_config(
    provider: Arc<CryptoProvider>,
    verifier: CloudSqlVerifier,
    client_cert: Vec<CertificateDer<'static>>,
    client_key: PrivateKeyDer<'static>,
) -> Result<ClientConfig, rustls::Error> {
    ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(client_cert, client_key)
}

/// The default endpoint of the Cloud SQL Admin API.
pub(crate) const DEFAULT_ENDPOINT: &str = "https://sqladmin.googleapis.com";

/// Same as `maxRetries` in `retry50x` of the Go connector.
const MAX_ATTEMPTS: u32 = 5;

static CLIENT_KEY: OnceCell<Arc<ClientKey>> = OnceCell::const_new();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_key() {
        let key = ClientKey::generate().unwrap();
        assert!(
            key.public_key_pem
                .starts_with("-----BEGIN PUBLIC KEY-----\n")
        );
        assert!(key.public_key_pem.ends_with("-----END PUBLIC KEY-----\n"));
        assert!(key.public_key_pem.lines().all(|line| line.len() <= 64));
    }

    #[test]
    fn backoff_grows() {
        assert_eq!(backoff(1), Duration::from_millis(200));
        assert!(backoff(2) > Duration::from_millis(320));
        assert!(backoff(4) < Duration::from_secs(1));
    }
}
