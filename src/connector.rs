use std::collections::HashMap;
use std::fmt;
use std::io;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use google_cloud_auth::credentials::{self, AccessTokenCredentials, Credentials};
use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::Error;
use crate::admin::{AdminFetch, DEFAULT_ENDPOINT, installed_provider};
use crate::refresh::{Cache, ConnectionInfo, Fetch, LazyCache, RefreshAheadCache};

/// A TLS connection to a Cloud SQL instance. The database protocol runs directly in it.
pub type CloudSqlStream = TlsStream<TcpStream>;

/// The IP address type to connect to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IpType {
    /// The public IP address of the instance.
    #[default]
    Public,
    /// The private IP address of the instance, in a VPC network.
    Private,
    /// The Private Service Connect DNS name of the instance.
    Psc,
}

impl IpType {
    fn as_str(self) -> &'static str {
        match self {
            IpType::Public => "public",
            IpType::Private => "private",
            IpType::Psc => "PSC",
        }
    }
}

/// When the connector refreshes the ephemeral certificate of an instance.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum RefreshStrategy {
    /// Refresh in a background task before the certificate expires.
    #[default]
    RefreshAhead,
    /// Refresh only when a connection opens and the certificate expires soon. Use it when
    /// the platform throttles the CPU between requests, for example Cloud Run.
    Lazy,
}

/// Opens TLS connections to Cloud SQL instances and caches a certificate per instance.
/// Clones share the cache. Uses the rustls `CryptoProvider` that the application installs.
///
/// ```no_run
/// # async fn example() -> Result<(), sqlx_cloudsql::Error> {
/// use sqlx_cloudsql::{Connector, RefreshStrategy};
///
/// let connector = Connector::builder()
///     .refresh_strategy(RefreshStrategy::Lazy)
///     .iam_authn(true)
///     .build()
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Connector {
    inner: Arc<ConnectorInner>,
}

#[derive(Debug)]
struct ConnectorInner {
    fetcher: Arc<dyn Fetch>,
    refresh_strategy: RefreshStrategy,
    ip_type: IpType,
    caches: Mutex<HashMap<InstanceConnectionName, Arc<Cache>>>,
}

impl Connector {
    /// Returns a builder for a connector.
    pub fn builder() -> ConnectorBuilder {
        ConnectorBuilder::default()
    }

    pub(crate) fn with_fetcher(
        fetcher: Arc<dyn Fetch>,
        refresh_strategy: RefreshStrategy,
        ip_type: IpType,
    ) -> Self {
        Self {
            inner: Arc::new(ConnectorInner {
                fetcher,
                refresh_strategy,
                ip_type,
                caches: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Opens a TLS connection to the instance.
    pub async fn connect(&self, name: &InstanceConnectionName) -> Result<CloudSqlStream, Error> {
        self.connect_inner(name, None).await
    }

    /// Opens a TLS connection to an instance whose database version starts with
    /// `engine`, for example `POSTGRES`.
    #[cfg(any(feature = "postgres", feature = "mysql"))]
    pub(crate) async fn connect_engine(
        &self,
        name: &InstanceConnectionName,
        engine: &str,
    ) -> Result<CloudSqlStream, Error> {
        self.connect_inner(name, Some(engine)).await
    }

    /// Returns the database version of the instance, for example `POSTGRES_17`.
    pub async fn engine_version(&self, name: &InstanceConnectionName) -> Result<String, Error> {
        let info = self.info_or_evict(name, &self.cache(name)).await?;
        Ok(info.database_version.clone())
    }

    /// Opens a TLS connection. On errors it evicts the cache or forces a refresh, same as
    /// `Dialer.Dial` in the Go connector.
    async fn connect_inner(
        &self,
        name: &InstanceConnectionName,
        engine: Option<&str>,
    ) -> Result<CloudSqlStream, Error> {
        let cache = self.cache(name);

        let mut info = self.info_or_evict(name, &cache).await?;
        if info.expiry <= SystemTime::now() {
            tracing::debug!(instance = %name, "Cloud SQL certificate expired, forcing refresh");
            cache.force_refresh();
            info = self.info_or_evict(name, &cache).await?;
        }

        if let Some(engine) = engine
            && !info.database_version.starts_with(engine)
        {
            return Err(Error::Config(format!(
                "instance {name} is a {} instance, not a {engine} instance",
                info.database_version
            )));
        }

        let ip_type = self.inner.ip_type;
        let Some(addr) = info.addrs.get(&ip_type) else {
            self.remove_cached(name, &cache);
            return Err(Error::Config(format!(
                "instance {name} has no {} IP address",
                ip_type.as_str()
            )));
        };

        let tcp = match connect_tcp(&addr.host).await {
            Ok(tcp) => tcp,
            Err(error) => {
                cache.force_refresh();
                return Err(error.into());
            }
        };

        let connector = TlsConnector::from(info.tls_config.clone());
        match connector.connect(addr.server_name.clone(), tcp).await {
            Ok(stream) => Ok(stream),
            Err(error) => {
                // A TLS handshake error requires a refresh. Remove the instance from
                // the cache, so that the next connect waits for a new certificate.
                tracing::debug!(instance = %name, %error, "Cloud SQL TLS handshake failed");
                self.remove_cached(name, &cache);
                Err(Error::Handshake {
                    instance: name.to_string(),
                    source: Arc::new(error),
                })
            }
        }
    }

    /// Returns the connection info of `cache`. On an error it removes the instance from
    /// the cache, so that the next connect starts a new refresh.
    async fn info_or_evict(
        &self,
        name: &InstanceConnectionName,
        cache: &Arc<Cache>,
    ) -> Result<Arc<ConnectionInfo>, Error> {
        let result = cache.connection_info().await;
        if result.is_err() {
            self.remove_cached(name, cache);
        }
        result
    }

    fn cache(&self, name: &InstanceConnectionName) -> Arc<Cache> {
        let mut caches = self.inner.caches.lock().unwrap();
        if let Some(cache) = caches.get(name) {
            return cache.clone();
        }
        caches
            .entry(name.clone())
            .or_insert_with(|| {
                let fetcher = self.inner.fetcher.clone();
                Arc::new(match self.inner.refresh_strategy {
                    RefreshStrategy::RefreshAhead => {
                        Cache::RefreshAhead(RefreshAheadCache::new(name.clone(), fetcher))
                    }
                    RefreshStrategy::Lazy => Cache::Lazy(LazyCache::new(name.clone(), fetcher)),
                })
            })
            .clone()
    }

    /// Removes `cache` from the cache map, if a concurrent connect did not replace it.
    fn remove_cached(&self, name: &InstanceConnectionName, cache: &Arc<Cache>) {
        let mut caches = self.inner.caches.lock().unwrap();
        if caches.get(name).is_some_and(|c| Arc::ptr_eq(c, cache)) {
            caches.remove(name);
        }
    }
}

/// Builds a [`Connector`]. Same as the `Option`s of `cloudsqlconn.NewDialer` in the Go
/// connector.
#[derive(Debug, Default)]
#[must_use]
pub struct ConnectorBuilder {
    credentials: Option<Credentials>,
    iam_login_credentials: Option<AccessTokenCredentials>,
    iam_authn: bool,
    ip_type: IpType,
    refresh_strategy: RefreshStrategy,
    admin_api_endpoint: Option<String>,
}

impl ConnectorBuilder {
    /// Sets the Admin API credentials. The default is Application Default Credentials.
    pub fn credentials(mut self, credentials: Credentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    /// Enables IAM database authentication. Leave the password out of the connect options
    /// and use the IAM user name.
    pub fn iam_authn(mut self, enabled: bool) -> Self {
        self.iam_authn = enabled;
        self
    }

    /// Sets the credentials for the IAM login token. The default is Application Default Credentials.
    pub fn iam_login_credentials(mut self, credentials: AccessTokenCredentials) -> Self {
        self.iam_login_credentials = Some(credentials);
        self
    }

    /// Sets the IP address type to connect to. The default is [`IpType::Public`].
    pub fn ip_type(mut self, ip_type: IpType) -> Self {
        self.ip_type = ip_type;
        self
    }

    /// Sets when the connector refreshes certificates. The default is
    /// [`RefreshStrategy::RefreshAhead`].
    pub fn refresh_strategy(mut self, strategy: RefreshStrategy) -> Self {
        self.refresh_strategy = strategy;
        self
    }

    /// Sets the endpoint of the Cloud SQL Admin API. The default is
    /// `https://sqladmin.googleapis.com`.
    pub fn admin_api_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.admin_api_endpoint = Some(endpoint.into());
        self
    }

    /// Builds the connector. Fails if no rustls `CryptoProvider` is installed.
    pub async fn build(self) -> Result<Connector, Error> {
        let provider = installed_provider()?;

        let credentials = match self.credentials {
            Some(credentials) => credentials,
            None => credentials::Builder::default()
                .build()
                .map_err(Error::auth)?,
        };

        let iam_login = if self.iam_authn {
            Some(match self.iam_login_credentials {
                Some(credentials) => credentials,
                None => credentials::Builder::default()
                    .with_scopes([LOGIN_SCOPE])
                    .build_access_token_credentials()
                    .map_err(Error::auth)?,
            })
        } else {
            None
        };

        let endpoint = self
            .admin_api_endpoint
            .as_deref()
            .unwrap_or(DEFAULT_ENDPOINT);
        let fetcher = AdminFetch::new(endpoint, credentials, provider, iam_login).await?;

        Ok(Connector::with_fetcher(
            Arc::new(fetcher),
            self.refresh_strategy,
            self.ip_type,
        ))
    }
}

async fn connect_tcp(host: &str) -> io::Result<TcpStream> {
    let tcp = TcpStream::connect((host, SERVER_PROXY_PORT)).await?;
    tcp.set_nodelay(true)?;

    let keepalive = TcpKeepalive::new()
        .with_time(TCP_KEEPALIVE)
        .with_interval(TCP_KEEPALIVE);
    SockRef::from(&tcp).set_tcp_keepalive(&keepalive)?;

    Ok(tcp)
}

/// An instance connection name `project:region:instance`. The project can be domain-scoped.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct InstanceConnectionName {
    project: String,
    region: String,
    name: String,
}

impl InstanceConnectionName {
    /// The project ID, including the domain for a domain-scoped project.
    pub fn project(&self) -> &str {
        &self.project
    }

    /// The region of the instance, for example `us-central1`.
    pub fn region(&self) -> &str {
        &self.region
    }

    /// The name of the instance.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The common name that a server certificate from the legacy
    /// `GOOGLE_MANAGED_INTERNAL_CA` has: `project:instance`.
    pub(crate) fn legacy_common_name(&self) -> String {
        format!("{}:{}", self.project, self.name)
    }
}

impl FromStr for InstanceConnectionName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Split from the end, because a domain-scoped project contains a colon.
        let mut parts = s.rsplitn(3, ':');
        let (Some(name), Some(region), Some(project)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(invalid(s));
        };

        // A domain-scoped project has exactly one colon: `domain:project`.
        let project_ok = match project.split_once(':') {
            Some((domain, project)) => {
                !domain.is_empty() && !project.is_empty() && !project.contains(':')
            }
            None => !project.is_empty(),
        };

        if !project_ok || region.is_empty() || name.is_empty() {
            return Err(invalid(s));
        }

        Ok(Self {
            project: project.into(),
            region: region.into(),
            name: name.into(),
        })
    }
}

impl fmt::Display for InstanceConnectionName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.project, self.region, self.name)
    }
}

fn invalid(s: &str) -> Error {
    Error::Config(format!(
        "invalid instance connection name {s:?}: expected \"project:region:instance\""
    ))
}

/// The port of the server-side proxy on a Cloud SQL instance.
const SERVER_PROXY_PORT: u16 = 3307;

/// Same as the `KeepAlive` of the `net.Dialer` in the Go connector.
const TCP_KEEPALIVE: Duration = Duration::from_secs(30);

/// The OAuth2 scope for the IAM database login token.
const LOGIN_SCOPE: &str = "https://www.googleapis.com/auth/sqlservice.login";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refresh::test_util::MockFetch;

    fn name() -> InstanceConnectionName {
        "p:r:i".parse().unwrap()
    }

    #[tokio::test]
    async fn api_error_removes_instance_from_cache() {
        let error = Error::api(std::io::Error::other("unavailable"), true);
        let fetcher = MockFetch::new(vec![Err(error)]);
        let connector =
            Connector::with_fetcher(fetcher.clone(), RefreshStrategy::Lazy, IpType::Public);

        assert!(connector.engine_version(&name()).await.is_err());
        assert!(connector.inner.caches.lock().unwrap().is_empty());

        assert_eq!(
            connector.engine_version(&name()).await.unwrap(),
            "POSTGRES_17"
        );
        assert_eq!(fetcher.calls(), 2);
    }

    #[tokio::test]
    async fn missing_ip_type_is_a_config_error() {
        let fetcher = MockFetch::new(vec![]);
        let connector =
            Connector::with_fetcher(fetcher, RefreshStrategy::RefreshAhead, IpType::Private);

        let error = connector.connect(&name()).await.unwrap_err();
        assert!(matches!(error, Error::Config(_)), "{error}");
        assert!(!error.is_retryable());
    }

    #[tokio::test]
    async fn tcp_error_is_retryable() {
        // The mock returns 127.0.0.1. Nothing listens on port 3307 in the test.
        let fetcher = MockFetch::new(vec![]);
        let connector = Connector::with_fetcher(fetcher, RefreshStrategy::Lazy, IpType::Public);

        let error = connector.connect(&name()).await.unwrap_err();
        assert!(error.is_retryable(), "{error}");
    }

    #[test]
    fn parses_connection_name() {
        let name: InstanceConnectionName = "my-project:us-central1:my-instance".parse().unwrap();
        assert_eq!(name.project(), "my-project");
        assert_eq!(name.region(), "us-central1");
        assert_eq!(name.name(), "my-instance");
        assert_eq!(name.legacy_common_name(), "my-project:my-instance");
        assert_eq!(name.to_string(), "my-project:us-central1:my-instance");
    }

    #[test]
    fn parses_domain_scoped_project() {
        let name: InstanceConnectionName = "example.com:my-project:us-central1:my-instance"
            .parse()
            .unwrap();
        assert_eq!(name.project(), "example.com:my-project");
        assert_eq!(name.region(), "us-central1");
        assert_eq!(name.name(), "my-instance");
    }

    #[test]
    fn rejects_invalid_names() {
        for s in [
            "",
            "my-instance",
            "my-project:my-instance",
            "my-project::my-instance",
            ":us-central1:my-instance",
            "my-project:us-central1:",
            "a:b:c:d:e",
            ":p:us-central1:i",
        ] {
            assert!(s.parse::<InstanceConnectionName>().is_err(), "{s:?}");
        }
    }
}
