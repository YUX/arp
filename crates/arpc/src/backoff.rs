use rand::RngExt;
use std::time::Duration;

/// Exponential backoff with randomized jitter.
#[derive(Debug)]
pub struct ExponentialBackoff {
    initial: Duration,
    max: Duration,
    factor: f64,
    current: Duration,
}

impl ExponentialBackoff {
    /// Creates a new `ExponentialBackoff` with the given parameters.
    ///
    /// # Examples
    ///
    /// ```
    /// use arpc::backoff::ExponentialBackoff;
    /// use std::time::Duration;
    /// let mut backoff = ExponentialBackoff::new(
    ///     Duration::from_millis(100),
    ///     Duration::from_millis(5000),
    ///     2.0,
    /// );
    /// let delay = backoff.next_delay();
    /// assert!(delay >= Duration::from_millis(75)); // 100ms * 0.75 jitter
    /// assert!(delay <= Duration::from_millis(125)); // 100ms * 1.25 jitter
    /// ```
    #[must_use]
    pub const fn new(initial: Duration, max: Duration, factor: f64) -> Self {
        Self {
            initial,
            max,
            factor,
            current: initial,
        }
    }

    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        clippy::cast_sign_loss
    )]
    /// Compute the next delay (with jitter) and advance the internal state.
    pub fn next_delay(&mut self) -> Duration {
        let current_ms = self.current.as_millis().min(u128::from(u64::MAX)) as u64;

        // Apply jitter to the current delay before advancing
        let jitter_factor = rand::rng().random_range(0.75..=1.25);
        let jittered_ms = (current_ms as f64 * jitter_factor) as u64;
        let delay = Duration::from_millis(jittered_ms);

        // Advance state for next call
        let next_ms = (current_ms as f64 * self.factor) as u64;
        let next = Duration::from_millis(next_ms.min(self.max.as_millis() as u64));
        self.current = next.min(self.max);

        delay
    }

    /// Reset the backoff to its initial delay.
    pub fn reset(&mut self) {
        self.current = self.initial;
    }

    /// Peek at the current delay without advancing state (no jitter).
    #[must_use]
    pub const fn peek(&self) -> Duration {
        self.current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_next_delay_returns_duration_greater_than_zero() {
        let mut backoff =
            ExponentialBackoff::new(Duration::from_millis(100), Duration::from_millis(5000), 2.0);

        let delay = backoff.next_delay();
        assert!(delay > Duration::ZERO);
    }

    #[test]
    fn test_delays_grow_with_jitter_accounting() {
        let initial = Duration::from_millis(100);
        let mut backoff = ExponentialBackoff::new(initial, Duration::from_millis(5000), 2.0);

        let mut delays: Vec<Duration> = Vec::new();
        for _ in 0..10 {
            delays.push(backoff.next_delay());
        }

        let first_avg = (delays[0].as_millis() + delays[1].as_millis()) / 2;
        let later_avg = (delays[7].as_millis() + delays[8].as_millis() + delays[9].as_millis()) / 3;

        assert!(
            later_avg >= first_avg || later_avg >= initial.as_millis() * 10,
            "Delays should generally increase over time"
        );
    }

    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn test_delays_never_exceed_max() {
        let max = Duration::from_millis(1000);
        let mut backoff = ExponentialBackoff::new(Duration::from_millis(100), max, 2.0);

        for _ in 0..20 {
            let delay = backoff.next_delay();
            let max_with_jitter = max.as_millis() as f64 * 1.25;
            assert!(
                delay.as_millis() as f64 <= max_with_jitter + 1.0,
                "Delay {delay:?} exceeds max_with_jitter {max_with_jitter:?}"
            );
        }
    }

    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn test_reset_returns_delay_back_to_initial_range() {
        let initial = Duration::from_millis(100);
        let mut backoff = ExponentialBackoff::new(initial, Duration::from_millis(5000), 2.0);

        for _ in 0..10 {
            backoff.next_delay();
        }

        backoff.reset();

        let post_reset_delay = backoff.next_delay();
        let min_expected = initial.as_millis() as f64 * 0.75;
        let max_expected = initial.as_millis() as f64 * 1.25;

        assert!(
            post_reset_delay.as_millis() as f64 >= min_expected - 1.0
                && post_reset_delay.as_millis() as f64 <= max_expected + 1.0,
            "Post-reset delay {post_reset_delay:?} not in expected range [{min_expected:?}, {max_expected:?}]"
        );
    }

    #[test]
    fn test_overflow_safety_with_large_max() {
        let initial = Duration::from_millis(100);
        let max = Duration::from_millis(u64::MAX);
        let mut backoff = ExponentialBackoff::new(initial, max, 2.0);

        for _ in 0..100 {
            let delay = backoff.next_delay();
            assert!(delay > Duration::ZERO);
        }
    }

    #[test]
    fn test_factor_of_one_grows_slowly() {
        let initial = Duration::from_millis(100);
        let mut backoff = ExponentialBackoff::new(initial, Duration::from_millis(5000), 1.0);

        let delay1 = backoff.next_delay();
        let delay2 = backoff.next_delay();
        let delay3 = backoff.next_delay();

        for delay in [delay1, delay2, delay3] {
            assert!(
                delay.as_millis() >= 50 && delay.as_millis() <= 150,
                "With factor 1.0, delay should stay around initial value"
            );
        }
    }
}
