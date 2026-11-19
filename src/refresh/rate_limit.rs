use std::time::Duration;

use tokio::time::Instant;

/// A token bucket rate limiter, same as `rate.NewLimiter(rate.Every(interval), burst)` in Go.
#[derive(Debug)]
pub(crate) struct RateLimiter {
    interval: Duration,
    burst: u32,
    /// The time at which the bucket is empty again ("theoretical arrival time").
    tat: Instant,
}

impl RateLimiter {
    pub(crate) fn new(interval: Duration, burst: u32) -> Self {
        assert!(burst > 0);
        Self {
            interval,
            burst,
            tat: Instant::now(),
        }
    }

    /// Waits until one more operation is allowed.
    pub(crate) async fn acquire(&mut self) {
        let now = Instant::now();
        let tat = self.tat.max(now);
        let allowed_at = tat
            .checked_sub(self.interval * (self.burst - 1))
            .unwrap_or(now);

        if allowed_at > now {
            tokio::time::sleep_until(allowed_at).await;
        }

        self.tat = tat + self.interval;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn allows_burst_then_one_per_interval() {
        let interval = Duration::from_secs(30);
        let mut limiter = RateLimiter::new(interval, 2);
        let start = Instant::now();

        limiter.acquire().await;
        limiter.acquire().await;
        assert_eq!(start.elapsed(), Duration::ZERO);

        limiter.acquire().await;
        assert_eq!(start.elapsed(), interval);

        limiter.acquire().await;
        assert_eq!(start.elapsed(), 2 * interval);
    }

    #[tokio::test(start_paused = true)]
    async fn refills_after_idle() {
        let interval = Duration::from_secs(30);
        let mut limiter = RateLimiter::new(interval, 2);

        limiter.acquire().await;
        limiter.acquire().await;
        tokio::time::sleep(10 * interval).await;

        let start = Instant::now();
        limiter.acquire().await;
        limiter.acquire().await;
        assert_eq!(start.elapsed(), Duration::ZERO);
    }
}
