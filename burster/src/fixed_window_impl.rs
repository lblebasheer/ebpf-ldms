//! Fixed window -type limiter

use core::time::Duration;

#[cfg(feature = "std")]
use crate::macros::std_time_provider;
use crate::{CantConsume, Limiter, LimiterResult};

/// Build a fixed window limiter
///
/// # Arguments
/// * `capacity` - how many consumes are allowed during a single window
/// * `window_width_ms` - window width in milliseconds
#[cfg(feature = "std")]
pub fn fixed_window(capacity: u64, window_width_ms: u64) -> FixedWindow<impl Fn() -> Duration> {
    FixedWindow::new_with_time_provider(capacity, window_width_ms, std_time_provider!())
}

/// Fixed window -type rate limiter
///
/// A Fixed window limiter splits the timeline into time windows
/// of defined size and allocates a certain amount of tokens for
/// each window. Consumes are successfull as long as the current
/// time window still holds enought tokens.
pub struct FixedWindow<T>
where
    T: Fn() -> Duration,
{
    config: FixedWindowConfig<T>,
    tokens: u64,
    window_index: u64,
    start_time: Duration,
}

impl<T> FixedWindow<T>
where
    T: Fn() -> Duration,
{
    /// Initialize a new fixed window limiter utilizing the given timer
    ///
    /// # Arguments
    /// * `capacity` - how many consumes are allowed during a single window
    /// * `window_width_ms` - window width in milliseconds
    /// * `time_provider_t` - closure that returns a monotonically nondecreasing
    ///   timestamp as [`Duration`] from some fixed epoch in the past
    ///
    /// If you are developing for a `std` target, you probably wish to use [`fixed_window`]
    pub fn new_with_time_provider(capacity: u64, window_width_ms: u64, time_provider: T) -> Self {
        let time_now = time_provider();
        let config = FixedWindowConfig::new(capacity, window_width_ms, time_provider);
        Self {
            config,
            tokens: capacity,
            window_index: 0,
            start_time: time_now,
        }
    }
}

impl<T> Limiter for FixedWindow<T>
where
    T: Fn() -> Duration,
{
    fn try_consume(&mut self, tokens: u64) -> LimiterResult {
        // Get current window index
        let now = (self.config.time_provider)();
        let delta_t = now.saturating_sub(self.start_time);
        let index = delta_t.as_millis() as u64 / self.config.width_ms;

        if index != self.window_index {
            // New window. Replenish tokens.
            self.tokens = self.config.capacity;
            self.window_index = index;
        }

        self.tokens = self.tokens.checked_sub(tokens).ok_or(CantConsume)?;
        Ok(())
    }
}

/// Configuration for a fixed window limiter
#[derive(Clone, Copy)]
struct FixedWindowConfig<T>
where
    T: Fn() -> Duration,
{
    capacity: u64,
    width_ms: u64,
    time_provider: T,
}

impl<T: Fn() -> Duration> FixedWindowConfig<T> {
    fn new(capacity: u64, width_ms: u64, time_provider: T) -> Self {
        Self {
            capacity,
            width_ms,
            time_provider,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{mock_assets::MockClock, Limiter};

    use super::FixedWindow;

    #[test]
    fn verify_rate() {
        let clock = MockClock::new();
        // Each call steps the clock 100us forward
        let mut w = FixedWindow::new_with_time_provider(1000, 1, || clock.step(100));

        // T = 100us, tokens left = 1000
        assert!(w.try_consume(500).is_ok());
        // T = 200us, tokens left = 500
        assert!(w.try_consume(500).is_ok());
        // T = 300us, tokens left = 0
        assert!(w.try_consume_one().is_err());
        // T = 400us, tokens left = 0
        assert!(w.try_consume_one().is_err());
        // T = 500us, tokens left = 0
        assert!(w.try_consume_one().is_err());
        // T = 600us, tokens left = 0
        assert!(w.try_consume_one().is_err());
        // T = 700us, tokens left = 0
        assert!(w.try_consume_one().is_err());
        // T = 800us, tokens left = 0
        assert!(w.try_consume_one().is_err());
        // T = 900us, tokens left = 0
        assert!(w.try_consume_one().is_err());
        // T = 1000us, tokens left = 1000
        assert!(w.try_consume_one().is_ok());
        // T = 1100us, tokens left = 999
        assert!(w.try_consume(998).is_ok());
        // T = 1100us, tokens left = 1
        assert!(w.try_consume(2).is_err());
    }
}
