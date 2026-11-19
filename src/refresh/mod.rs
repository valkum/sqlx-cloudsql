use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::SystemTime;

use rustls::ClientConfig;
use rustls::pki_types::ServerName;

use crate::{Error, InstanceConnectionName, IpType};

mod lazy;
mod rate_limit;
mod refresh_ahead;
pub(crate) mod timing;

pub(crate) use lazy::LazyCache;
pub(crate) use refresh_ahead::RefreshAheadCache;

/// The addresses, TLS configuration and expiry of an instance.
#[derive(Debug)]
pub(crate) struct ConnectionInfo {
    pub(crate) addrs: HashMap<IpType, Addr>,
    pub(crate) database_version: String,
    pub(crate) tls_config: Arc<ClientConfig>,
    /// The expiry of the client certificate.
    pub(crate) expiry: SystemTime,
    /// A hash of the IAM login token in the certificate, if IAM authentication is enabled.
    pub(crate) login_token: Option<u64>,
}

/// The host to connect to for an IP type, and the TLS server name to use.
#[derive(Debug)]
pub(crate) struct Addr {
    pub(crate) host: String,
    pub(crate) server_name: ServerName<'static>,
}

pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Gets new connection info for an instance from the Cloud SQL Admin API.
pub(crate) trait Fetch: Send + Sync + 'static {
    fn fetch<'a>(
        &'a self,
        name: &'a InstanceConnectionName,
    ) -> BoxFuture<'a, Result<ConnectionInfo, Error>>;

    /// Returns `true` if the IAM login token is not the one in `info`. The certificate then
    /// needs a refresh before the old token expires.
    ///
    /// Workaround: google-cloud-auth does not expose the token expiry
    /// (googleapis/google-cloud-rust#7391), so Go's `min(NotAfter, token expiry)` is not possible.
    fn login_token_changed<'a>(&'a self, info: &'a ConnectionInfo) -> BoxFuture<'a, bool>;
}

impl std::fmt::Debug for dyn Fetch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Fetch")
    }
}

/// The connection info cache of one instance.
#[derive(Debug)]
pub(crate) enum Cache {
    RefreshAhead(RefreshAheadCache),
    Lazy(LazyCache),
}

impl Cache {
    /// Returns valid connection info. Waits for a refresh if necessary.
    pub(crate) async fn connection_info(&self) -> Result<Arc<ConnectionInfo>, Error> {
        match self {
            Cache::RefreshAhead(cache) => cache.connection_info().await,
            Cache::Lazy(cache) => cache.connection_info().await,
        }
    }

    /// Makes the next call to [`Cache::connection_info`] use new connection info.
    pub(crate) fn force_refresh(&self) {
        match self {
            Cache::RefreshAhead(cache) => cache.force_refresh(),
            Cache::Lazy(cache) => cache.force_refresh(),
        }
    }
}

#[cfg(test)]
pub(crate) mod test_util {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;

    /// A [`Fetch`] that returns results from a queue and counts the calls.
    pub(crate) struct MockFetch {
        pub(crate) calls: AtomicUsize,
        /// The answer of `login_token_changed`.
        pub(crate) token_changed: AtomicBool,
        results: Mutex<Vec<Result<Duration, Error>>>,
    }

    impl MockFetch {
        /// Each `Ok` is the validity of one result. An empty queue gives one hour.
        pub(crate) fn new(mut results: Vec<Result<Duration, Error>>) -> Arc<Self> {
            results.reverse();
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                token_changed: AtomicBool::new(false),
                results: Mutex::new(results),
            })
        }

        pub(crate) fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    pub(crate) fn connection_info(valid_for: Duration) -> ConnectionInfo {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let tls_config = ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();

        ConnectionInfo {
            addrs: HashMap::from([(
                IpType::Public,
                Addr {
                    host: "127.0.0.1".to_owned(),
                    server_name: ServerName::try_from("127.0.0.1").unwrap(),
                },
            )]),
            database_version: "POSTGRES_17".to_owned(),
            tls_config: Arc::new(tls_config),
            expiry: SystemTime::now() + valid_for,
            login_token: None,
        }
    }

    impl Fetch for MockFetch {
        fn fetch<'a>(
            &'a self,
            _name: &'a InstanceConnectionName,
        ) -> BoxFuture<'a, Result<ConnectionInfo, Error>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let result = self
                .results
                .lock()
                .unwrap()
                .pop()
                .unwrap_or(Ok(Duration::from_secs(60 * 60)));
            Box::pin(async move { result.map(connection_info) })
        }

        fn login_token_changed<'a>(&'a self, _info: &'a ConnectionInfo) -> BoxFuture<'a, bool> {
            let changed = self.token_changed.load(Ordering::SeqCst);
            Box::pin(async move { changed })
        }
    }
}
