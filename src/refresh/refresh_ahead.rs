use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::rate_limit::RateLimiter;
use super::timing::refresh_delay;
use super::{ConnectionInfo, Fetch};
use crate::{Error, InstanceConnectionName};

#[derive(Clone, Debug)]
enum State {
    /// The first refresh, or a forced refresh after the connection info became
    /// invalid, has not completed.
    Pending,
    Ready(Arc<ConnectionInfo>),
    Failed(Error),
}

impl State {
    fn is_valid(&self, now: SystemTime) -> bool {
        matches!(self, State::Ready(info) if info.expiry > now)
    }
}

/// Refreshes the connection info in a background task before it expires. A failed refresh
/// keeps info that is still valid. Port of `refresh_ahead.go` in the Go connector.
#[derive(Debug)]
pub(crate) struct RefreshAheadCache {
    state: watch::Sender<State>,
    force: Arc<Notify>,
    task: JoinHandle<()>,
}

impl RefreshAheadCache {
    pub(crate) fn new(name: InstanceConnectionName, fetcher: Arc<dyn Fetch>) -> Self {
        let state = watch::Sender::new(State::Pending);
        let force = Arc::new(Notify::new());
        let task = tokio::spawn(run(name, fetcher, state.clone(), force.clone()));

        Self { state, force, task }
    }

    pub(crate) async fn connection_info(&self) -> Result<Arc<ConnectionInfo>, Error> {
        let mut rx = self.state.subscribe();
        let state = rx
            .wait_for(|state| !matches!(state, State::Pending))
            .await
            .map_err(|_| Error::Config("the refresh task stopped".into()))?;

        match &*state {
            State::Ready(info) => Ok(info.clone()),
            State::Failed(error) => Err(error.clone()),
            State::Pending => unreachable!(),
        }
    }

    /// Starts a refresh now, or after the rate limit. Callers wait for it only if the current
    /// connection info is not valid.
    pub(crate) fn force_refresh(&self) {
        replace_if_invalid(&self.state, State::Pending);
        self.force.notify_one();
    }
}

impl Drop for RefreshAheadCache {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Replaces the state with `new`, unless the state is connection info that is still valid.
fn replace_if_invalid(state: &watch::Sender<State>, new: State) {
    let now = SystemTime::now();
    state.send_if_modified(|state| {
        if state.is_valid(now) {
            false
        } else {
            *state = new;
            true
        }
    });
}

async fn run(
    name: InstanceConnectionName,
    fetcher: Arc<dyn Fetch>,
    state: watch::Sender<State>,
    force: Arc<Notify>,
) {
    let mut limiter = RateLimiter::new(RATE_LIMIT_INTERVAL, RATE_LIMIT_BURST);

    loop {
        limiter.acquire().await;

        let delay = match fetcher.fetch(&name).await {
            Ok(info) => {
                let delay = refresh_delay(SystemTime::now(), info.expiry);
                tracing::debug!(
                    instance = %name,
                    next_refresh_in = ?delay,
                    "refreshed Cloud SQL connection info"
                );
                state.send_replace(State::Ready(Arc::new(info)));
                delay
            }
            Err(error) => {
                tracing::debug!(instance = %name, %error, "failed to refresh Cloud SQL connection info");
                replace_if_invalid(&state, State::Failed(error));
                Duration::ZERO
            }
        };

        wait_for_refresh(&fetcher, &state, &force, delay).await;
    }
}

/// Waits `delay`, a forced refresh, or a new IAM login token, which the task checks every
/// [`TOKEN_CHECK_INTERVAL`].
async fn wait_for_refresh(
    fetcher: &Arc<dyn Fetch>,
    state: &watch::Sender<State>,
    force: &Notify,
    delay: Duration,
) {
    let deadline = Instant::now() + delay;
    loop {
        let wake = deadline.min(Instant::now() + TOKEN_CHECK_INTERVAL);
        tokio::select! {
            () = tokio::time::sleep_until(wake) => {}
            () = force.notified() => return,
        }
        if Instant::now() >= deadline {
            return;
        }

        let info = match &*state.borrow() {
            State::Ready(info) => info.clone(),
            _ => continue,
        };
        if fetcher.login_token_changed(&info).await {
            tracing::debug!("IAM login token changed, refreshing Cloud SQL connection info");
            return;
        }
    }
}

/// Same as the rate limit of the refresh-ahead cache in the Go connector: two refreshes
/// at once, then one refresh every 30 seconds.
const RATE_LIMIT_INTERVAL: Duration = Duration::from_secs(30);
const RATE_LIMIT_BURST: u32 = 2;

/// How often the background task checks for a new IAM login token.
const TOKEN_CHECK_INTERVAL: Duration = Duration::from_secs(30);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refresh::test_util::MockFetch;
    use std::sync::atomic::Ordering;

    const MIN: Duration = Duration::from_secs(60);

    fn name() -> InstanceConnectionName {
        "p:r:i".parse().unwrap()
    }

    fn api_error() -> Error {
        Error::api(std::io::Error::other("unavailable"), true)
    }

    #[tokio::test(start_paused = true)]
    async fn waits_for_first_refresh() {
        let fetcher = MockFetch::new(vec![]);
        let cache = RefreshAheadCache::new(name(), fetcher.clone());

        cache.connection_info().await.unwrap();
        cache.connection_info().await.unwrap();
        assert_eq!(fetcher.calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn refreshes_ahead_of_expiry() {
        // 10 minutes of validity: the next refresh is 4 minutes before expiry.
        let fetcher = MockFetch::new(vec![Ok(10 * MIN)]);
        let cache = RefreshAheadCache::new(name(), fetcher.clone());
        cache.connection_info().await.unwrap();

        tokio::time::sleep(6 * MIN - Duration::from_secs(1)).await;
        assert_eq!(fetcher.calls(), 1);

        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(fetcher.calls(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn returns_error_then_retries() {
        // The burst allows two refreshes at once. The third waits for the rate limit.
        let fetcher = MockFetch::new(vec![Err(api_error()), Err(api_error())]);
        let cache = RefreshAheadCache::new(name(), fetcher.clone());

        let result = cache.connection_info().await;
        assert!(matches!(result, Err(Error::Api { .. })), "{result:?}");

        tokio::time::sleep(RATE_LIMIT_INTERVAL + Duration::from_secs(1)).await;
        cache.connection_info().await.unwrap();
        assert_eq!(fetcher.calls(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn keeps_valid_info_when_refresh_fails() {
        let fetcher = MockFetch::new(vec![Ok(10 * MIN), Err(api_error()), Err(api_error())]);
        let cache = RefreshAheadCache::new(name(), fetcher.clone());
        cache.connection_info().await.unwrap();

        cache.force_refresh();
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(fetcher.calls() >= 2);
        cache.connection_info().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn force_refresh_is_rate_limited() {
        let fetcher = MockFetch::new(vec![]);
        let cache = RefreshAheadCache::new(name(), fetcher.clone());
        cache.connection_info().await.unwrap();

        for _ in 0..3 {
            cache.force_refresh();
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(fetcher.calls(), 2);

        tokio::time::sleep(RATE_LIMIT_INTERVAL).await;
        assert_eq!(fetcher.calls(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn drop_stops_the_task() {
        let fetcher = MockFetch::new(vec![Ok(10 * MIN)]);
        let cache = RefreshAheadCache::new(name(), fetcher.clone());
        cache.connection_info().await.unwrap();
        drop(cache);

        tokio::time::sleep(60 * MIN).await;
        assert_eq!(fetcher.calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn refreshes_after_new_login_token() {
        let fetcher = MockFetch::new(vec![]);
        let cache = RefreshAheadCache::new(name(), fetcher.clone());
        cache.connection_info().await.unwrap();

        tokio::time::sleep(2 * TOKEN_CHECK_INTERVAL).await;
        assert_eq!(fetcher.calls(), 1);

        fetcher.token_changed.store(true, Ordering::SeqCst);
        tokio::time::sleep(TOKEN_CHECK_INTERVAL + Duration::from_secs(1)).await;
        assert!(fetcher.calls() >= 2);
    }
}
