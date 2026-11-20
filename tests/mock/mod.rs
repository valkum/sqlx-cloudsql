//! A fake Cloud SQL instance, Admin API and server-side proxy. Port of `internal/mock` in the
//! Go connector.

// Each test binary uses only some of the helpers.
#![allow(dead_code)]

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
    SubjectPublicKeyInfo,
};
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex as AsyncMutex, MutexGuard};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

/// The fake server-side proxy listens on the real port, so tests that use it run one at a time.
static PROXY_PORT: AsyncMutex<()> = AsyncMutex::const_new(());

/// Installs the rustls provider for the tests. The crate uses the installed provider.
pub fn install_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// A certificate authority that signs server or client certificates.
pub struct Ca {
    issuer: Issuer<'static, KeyPair>,
    pem: String,
}

impl Ca {
    pub fn new(name: &str) -> Self {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let cert = params.self_signed(&key).unwrap();
        Self {
            pem: cert.pem(),
            issuer: Issuer::new(params, key),
        }
    }
}

/// The name in the server certificate of the fake instance.
#[derive(Clone)]
pub enum ServerName {
    /// The CN `project:instance`, as the legacy `GOOGLE_MANAGED_INTERNAL_CA` uses.
    LegacyCn(String),
    /// A DNS SAN, with a trailing dot as Cloud SQL uses.
    DnsSan(String),
}

/// A fake Cloud SQL instance. Same as `FakeCSQLInstance` in the Go connector.
pub struct FakeInstance {
    pub project: String,
    pub region: String,
    pub name: String,
    pub database_version: String,
    pub backend_type: String,
    pub public_ip: Option<String>,
    /// The DNS name in `dnsNames`, for the `PUBLIC` connection type.
    pub dns_name: Option<String>,
    pub server_name: ServerName,
    pub client_cert_validity: Duration,
    /// Signs the server certificate. The Admin API returns `ca` as the server CA.
    pub server_signer: Arc<Ca>,
    pub ca: Arc<Ca>,
}

impl FakeInstance {
    pub fn new(project: &str, region: &str, name: &str) -> Self {
        let ca = Arc::new(Ca::new("Fake Cloud SQL Server CA"));
        Self {
            project: project.into(),
            region: region.into(),
            name: name.into(),
            database_version: "POSTGRES_17".into(),
            backend_type: "SECOND_GEN".into(),
            public_ip: Some("127.0.0.1".into()),
            dns_name: None,
            server_name: ServerName::LegacyCn(format!("{project}:{name}")),
            client_cert_validity: Duration::from_secs(60 * 60),
            server_signer: ca.clone(),
            ca,
        }
    }

    pub fn connection_name(&self) -> sqlx_cloudsql::InstanceConnectionName {
        format!("{}:{}:{}", self.project, self.region, self.name)
            .parse()
            .unwrap()
    }

    /// A CAS instance: the server certificate has `dns_name` as SAN, with a trailing dot.
    pub fn with_dns_name(mut self, dns_name: &str) -> Self {
        self.dns_name = Some(dns_name.into());
        self.server_name = ServerName::DnsSan(format!("{dns_name}."));
        self
    }

    fn connect_settings(&self) -> Value {
        let ip_addresses: Vec<Value> = self
            .public_ip
            .iter()
            .map(|ip| json!({ "type": "PRIMARY", "ipAddress": ip }))
            .collect();
        let dns_names: Vec<Value> = self
            .dns_name
            .iter()
            .map(|name| {
                json!({
                    "name": format!("{name}."),
                    "connectionType": "PUBLIC",
                    "dnsScope": "INSTANCE",
                })
            })
            .collect();

        json!({
            "kind": "sql#connectSettings",
            "serverCaCert": { "cert": self.ca.pem },
            "ipAddresses": ip_addresses,
            "region": self.region,
            "databaseVersion": self.database_version,
            "backendType": self.backend_type,
            "dnsNames": dns_names,
        })
    }

    /// Signs `public_key_pem` into a client certificate, same as `generateEphemeralCert`.
    fn client_cert(&self, public_key_pem: &str) -> String {
        let public_key = SubjectPublicKeyInfo::from_pem(public_key_pem).unwrap();
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, "client");
        let now = OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::minutes(1);
        params.not_after = now + self.client_cert_validity;
        params
            .signed_by(&public_key, &self.ca.issuer)
            .unwrap()
            .pem()
    }

    /// The certificate chain and key of the fake server-side proxy.
    fn server_identity(&self) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        match &self.server_name {
            ServerName::LegacyCn(cn) => params.distinguished_name.push(DnType::CommonName, cn),
            ServerName::DnsSan(name) => {
                params.distinguished_name.push(DnType::CommonName, "server");
                params.subject_alt_names = vec![SanType::DnsName(
                    Ia5String::try_from(name.as_str()).unwrap(),
                )];
            }
        }
        let cert = params.signed_by(&key, &self.server_signer.issuer).unwrap();
        (
            vec![cert.der().clone()],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
    }
}

/// The requests that the fake Admin API got.
#[derive(Default)]
pub struct Calls {
    pub connect_settings: usize,
    pub ephemeral_cert: usize,
    /// The `access_token` of the last `generateEphemeralCert` request.
    pub access_token: Option<String>,
}

#[derive(Default)]
struct AdminState {
    calls: Calls,
    /// HTTP status codes to return before the next successful `connectSettings` responses.
    connect_settings_errors: VecDeque<u16>,
    /// HTTP status codes to return before the next successful `generateEphemeralCert` responses.
    ephemeral_cert_errors: VecDeque<u16>,
}

/// A fake Cloud SQL Admin API on a free local port. Same as `NewSQLAdminService` in the Go
/// connector.
pub struct FakeAdminApi {
    pub url: String,
    state: Arc<Mutex<AdminState>>,
    task: JoinHandle<()>,
}

impl FakeAdminApi {
    pub async fn start(instance: FakeInstance) -> (Self, Arc<FakeInstance>) {
        let instance = Arc::new(instance);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(AdminState::default()));

        let task = tokio::spawn({
            let (instance, state) = (instance.clone(), state.clone());
            async move {
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    let (instance, state) = (instance.clone(), state.clone());
                    let service =
                        service_fn(move |request| handle(request, instance.clone(), state.clone()));
                    tokio::spawn(
                        http1::Builder::new().serve_connection(TokioIo::new(stream), service),
                    );
                }
            }
        });

        (Self { url, state, task }, instance)
    }

    /// Makes the next `connectSettings` calls fail with these HTTP status codes.
    pub fn fail_connect_settings(&self, statuses: &[u16]) {
        self.state
            .lock()
            .unwrap()
            .connect_settings_errors
            .extend(statuses);
    }

    /// Makes the next `generateEphemeralCert` calls fail with these HTTP status codes.
    pub fn fail_ephemeral_cert(&self, statuses: &[u16]) {
        self.state
            .lock()
            .unwrap()
            .ephemeral_cert_errors
            .extend(statuses);
    }

    pub fn calls<T>(&self, f: impl FnOnce(&Calls) -> T) -> T {
        f(&self.state.lock().unwrap().calls)
    }
}

impl Drop for FakeAdminApi {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn handle(
    request: Request<Incoming>,
    instance: Arc<FakeInstance>,
    state: Arc<Mutex<AdminState>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = request.uri().path().to_owned();
    let prefix = format!(
        "/v1/projects/{}/instances/{}",
        instance.project, instance.name
    );

    if path == format!("{prefix}/connectSettings") {
        let error = {
            let mut state = state.lock().unwrap();
            state.calls.connect_settings += 1;
            state.connect_settings_errors.pop_front()
        };
        return Ok(match error {
            Some(status) => error_response(status),
            None => json_response(StatusCode::OK, instance.connect_settings()),
        });
    }

    if path == format!("{prefix}:generateEphemeralCert") {
        let body = request.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        let error = {
            let mut state = state.lock().unwrap();
            state.calls.ephemeral_cert += 1;
            state.calls.access_token = body["access_token"]
                .as_str()
                .filter(|token| !token.is_empty())
                .map(str::to_owned);
            state.ephemeral_cert_errors.pop_front()
        };
        if let Some(status) = error {
            return Ok(error_response(status));
        }
        let cert = instance.client_cert(body["public_key"].as_str().unwrap());
        return Ok(json_response(
            StatusCode::OK,
            json!({ "ephemeralCert": { "cert": cert } }),
        ));
    }

    Ok(error_response(404))
}

fn json_response(status: StatusCode, body: Value) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

fn error_response(status: u16) -> Response<Full<Bytes>> {
    let status = StatusCode::from_u16(status).unwrap();
    json_response(
        status,
        json!({ "error": { "code": status.as_u16(), "message": "fake error" } }),
    )
}

/// What the fake server-side proxy does with a connection after the TLS handshake.
pub enum Backend {
    /// Send back all data.
    Echo,
    /// Forward the connection to a database, without TLS.
    Forward(SocketAddr),
}

/// A fake server-side proxy on `127.0.0.1:3307`. Same as `StartServerProxy` in the Go
/// connector. It requires a client certificate that the instance CA signed.
pub struct FakeServerProxy {
    task: JoinHandle<()>,
    _port: MutexGuard<'static, ()>,
}

impl FakeServerProxy {
    pub async fn start(instance: &FakeInstance, backend: Backend) -> Self {
        let port = PROXY_PORT.lock().await;

        let mut client_roots = RootCertStore::empty();
        client_roots
            .add(CertificateDer::from_pem_slice(instance.ca.pem.as_bytes()).unwrap())
            .unwrap();
        let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .unwrap();
        let (chain, key) = instance.server_identity();
        let config =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_client_cert_verifier(client_verifier)
                .with_single_cert(chain, key)
                .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind("127.0.0.1:3307").await.unwrap();
        let backend = Arc::new(backend);
        let task = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let (acceptor, backend) = (acceptor.clone(), backend.clone());
                tokio::spawn(async move {
                    // A failed handshake is part of some tests.
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    match &*backend {
                        Backend::Echo => {
                            let (mut reader, mut writer) = tokio::io::split(tls);
                            let _ = tokio::io::copy(&mut reader, &mut writer).await;
                        }
                        Backend::Forward(addr) => {
                            let mut db = TcpStream::connect(addr).await.unwrap();
                            let _ = tokio::io::copy_bidirectional(&mut tls, &mut db).await;
                        }
                    }
                });
            }
        });

        Self { task, _port: port }
    }
}

impl Drop for FakeServerProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}
