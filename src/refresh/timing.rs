use std::time::{Duration, SystemTime};

/// Returns the wait before the next refresh: half the time left, or [`REFRESH_BUFFER`]
/// before expiry if less than one hour is left. Same as `refreshDuration` in Go.
pub(crate) fn refresh_delay(now: SystemTime, expiry: SystemTime) -> Duration {
    let left = expiry.duration_since(now).unwrap_or(Duration::ZERO);

    if left < Duration::from_secs(60 * 60) {
        left.saturating_sub(REFRESH_BUFFER)
    } else {
        left / 2
    }
}

/// Returns `true` if connection info that expires at `expiry` must be refreshed before use.
pub(crate) fn needs_refresh(now: SystemTime, expiry: SystemTime) -> bool {
    expiry
        .checked_sub(REFRESH_BUFFER)
        .is_none_or(|refresh_at| now >= refresh_at)
}

/// How long before expiry the connection info is refreshed. Same as `refreshBuffer` in Go.
pub(crate) const REFRESH_BUFFER: Duration = Duration::from_secs(4 * 60);

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: Duration = Duration::from_secs(60);

    fn at(offset: Duration) -> (SystemTime, SystemTime) {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        (now, now + offset)
    }

    #[test]
    fn long_validity_refreshes_at_half() {
        let (now, expiry) = at(60 * MIN);
        assert_eq!(refresh_delay(now, expiry), 30 * MIN);

        let (now, expiry) = at(24 * 60 * MIN);
        assert_eq!(refresh_delay(now, expiry), 12 * 60 * MIN);
    }

    #[test]
    fn short_validity_refreshes_before_buffer() {
        let (now, expiry) = at(59 * MIN);
        assert_eq!(refresh_delay(now, expiry), 55 * MIN);

        let (now, expiry) = at(5 * MIN);
        assert_eq!(refresh_delay(now, expiry), MIN);
    }

    #[test]
    fn almost_expired_refreshes_now() {
        let (now, expiry) = at(3 * MIN);
        assert_eq!(refresh_delay(now, expiry), Duration::ZERO);

        // Already expired.
        let (expiry, now) = at(MIN);
        assert_eq!(refresh_delay(now, expiry), Duration::ZERO);
    }

    #[test]
    fn lazy_refresh_threshold() {
        let (now, expiry) = at(5 * MIN);
        assert!(!needs_refresh(now, expiry));

        let (now, expiry) = at(4 * MIN);
        assert!(needs_refresh(now, expiry));

        let (now, expiry) = at(MIN);
        assert!(needs_refresh(now, expiry));
    }
}
