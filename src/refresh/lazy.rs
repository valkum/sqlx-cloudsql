use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

use tokio::sync::Mutex;

use super::timing::needs_refresh;
use super::{ConnectionInfo, Fetch};
use crate::{Error, InstanceConnectionName};

/// Refreshes the connection info in the caller when it expires within four minutes or
/// after a forced refresh. Port of `lazy.go` in the Go connector.
#[derive(Debug)]
pub(crate) struct LazyCache {
    name: InstanceConnectionName,
    fetcher: Arc<dyn Fetch>,
    cached: Mutex<Option<Arc<ConnectionInfo>>>,
    force: AtomicBool,
}

impl LazyCache {
    pub(crate) fn new(name: InstanceConnectionName, fetcher: Arc<dyn Fetch>) -> Self {
        Self {
            name,
            fetcher,
            cached: Mutex::new(None),
            force: AtomicBool::new(false),
        }
    }

    pub(crate) async fn connection_info(&self) -> Result<Arc<ConnectionInfo>, Error> {
        let mut cached = self.cached.lock().await;

        if let Some(info) = &*cached
            && !self.force.load(Ordering::SeqCst)
            && !needs_refresh(SystemTime::now(), info.expiry)
            && !self.fetcher.login_token_changed(info).await
        {
            return Ok(info.clone());
        }

        // Clear the flag before the fetch, so that a forced refresh during the fetch
        // causes one more refresh.
        self.force.store(false, Ordering::SeqCst);

        let info = match self.fetcher.fetch(&self.name).await {
            Ok(info) => Arc::new(info),
            Err(error) => {
                self.force.store(true, Ordering::SeqCst);
                tracing::debug!(instance = %self.name, %error, "failed to refresh Cloud SQL connection info");
                return Err(error);
            }
        };

        tracing::debug!(
            instance = %self.name,
            expires_in = ?info.expiry.duration_since(SystemTime::now()).unwrap_or_default(),
            "refreshed Cloud SQL connection info"
        );
        *cached = Some(info.clone());
        Ok(info)
    }

    pub(crate) fn force_refresh(&self) {
        self.force.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::refresh::test_util::MockFetch;

    const MIN: Duration = Duration::from_secs(60);

    fn name() -> InstanceConnectionName {
        "p:r:i".parse().unwrap()
    }

    #[tokio::test]
    async fn caches_valid_info() {
        let fetcher = MockFetch::new(vec![]);
        let cache = LazyCache::new(name(), fetcher.clone());

        cache.connection_info().await.unwrap();
        cache.connection_info().await.unwrap();
        assert_eq!(fetcher.calls(), 1);
    }

    #[tokio::test]
    async fn refreshes_info_that_expires_soon() {
        let fetcher = MockFetch::new(vec![Ok(3 * MIN)]);
        let cache = LazyCache::new(name(), fetcher.clone());

        cache.connection_info().await.unwrap();
        cache.connection_info().await.unwrap();
        cache.connection_info().await.unwrap();
        assert_eq!(fetcher.calls(), 2);
    }

    #[tokio::test]
    async fn force_refresh() {
        let fetcher = MockFetch::new(vec![]);
        let cache = LazyCache::new(name(), fetcher.clone());

        cache.connection_info().await.unwrap();
        cache.force_refresh();
        cache.connection_info().await.unwrap();
        assert_eq!(fetcher.calls(), 2);
    }

    #[tokio::test]
    async fn does_not_cache_errors() {
        let error = Error::api(std::io::Error::other("unavailable"), true);
        let fetcher = MockFetch::new(vec![Ok(10 * MIN), Err(error)]);
        let cache = LazyCache::new(name(), fetcher.clone());

        cache.connection_info().await.unwrap();
        cache.force_refresh();
        assert!(cache.connection_info().await.is_err());
        cache.connection_info().await.unwrap();
        assert_eq!(fetcher.calls(), 3);
    }

    #[tokio::test]
    async fn concurrent_callers_share_one_refresh() {
        let fetcher = MockFetch::new(vec![]);
        let cache = Arc::new(LazyCache::new(name(), fetcher.clone()));

        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let cache = cache.clone();
                tokio::spawn(async move { cache.connection_info().await.map(|_| ()) })
            })
            .collect();
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        assert_eq!(fetcher.calls(), 1);
    }

    #[tokio::test]
    async fn refreshes_after_new_login_token() {
        let fetcher = MockFetch::new(vec![]);
        let cache = LazyCache::new(name(), fetcher.clone());

        cache.connection_info().await.unwrap();
        fetcher.token_changed.store(true, Ordering::SeqCst);
        cache.connection_info().await.unwrap();
        assert_eq!(fetcher.calls(), 2);
    }
}
