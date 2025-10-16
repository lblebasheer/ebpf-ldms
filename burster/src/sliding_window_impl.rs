//! Sliding window -type limiter

use core::time::Duration;

#[cfg(feature = "std")]
use crate::macros::std_time_provider;
use crate::{CantConsume, Limiter, LimiterResult};

/// Build a sliding window limiter
///
/// Window width is defined by the generic argument `W: usize`
///
/// # Arguments
/// * `capacity` - how many consumes are allowed during a single window
#[cfg(feature = "std")]
pub fn sliding_window_log<const W: usize>(
    capacity: u64,
) -> SlidingWindowLog<impl Fn() -> Duration, W> {
    SlidingWindowLog::<_, W>::new_with_time_provider(capacity, std_time_provider!())
}

/// Build a sliding window counter limiter
///
/// # Arguments
/// * `capacity` - how many consumes are allowed during a single window
/// * `window_width_ms` - window width in milliseconds
#[cfg(feature = "std")]
pub fn sliding_window_counter(
    capacity: u64,
    window_width_ms: u64,
) -> SlidingWindowCounter<impl Fn() -> Duration> {
    SlidingWindowCounter::new_with_time_provider(capacity, window_width_ms, std_time_provider!())
}

/// Sliding window log -type rate limiter
///
/// A sliding windows limiter keeps track of tokens used
/// during the last `window_width` milliseconds before the
/// most recent consume and limits usage if that number grows
/// larger than the defined limit.
///
/// # Generic arguments
/// * `W` - Window width in milliseconds
///
/// # Notes
/// This limiter requires copying on each access with general complexity
/// of `O(window_width)`. If you are running on a low-powered target and
/// need a more performant variant, take a look at [`SlidingWindowCounter`].
pub struct SlidingWindowLog<T, const W: usize>
where
    T: Fn() -> Duration,
{
    config: SlidingWindowConfig<T>,
    /// Each slot represents a point in past time relative to current time.
    /// When time moves forward, we effectively shift the slots to right.
    window_buffer: [u64; W],
    last_update_time: Duration,
}

impl<T, const W: usize> SlidingWindowLog<T, W>
where
    T: Fn() -> Duration,
{
    /// Initialize a new sliding window limiter utilizing the given timer
    ///
    /// # Arguments
    /// * `capacity` - how many consumes are allowed during a single window
    /// * `time_provider_t` - closure that returns a monotonically nondecreasing
    ///   timestamp as [`Duration`] from some fixed epoch in the past

    ///
    /// # Notes
    /// * If you are developing for a `std` target, you probably wish to use [`sliding_window_log`]
    /// * Window width is defined by the generic argument `W: usize`
    pub fn new_with_time_provider(capacity: u64, time_provider: T) -> Self {
        let time_now = time_provider();
        let config = SlidingWindowConfig::new(capacity, time_provider);
        Self {
            config,
            window_buffer: [0; W],
            last_update_time: time_now,
        }
    }
}

impl<T, const W: usize> Limiter for SlidingWindowLog<T, W>
where
    T: Fn() -> Duration,
{
    fn try_consume(&mut self, tokens: u64) -> LimiterResult {
        let now = (self.config.time_provider)();
        let delta_t = now.saturating_sub(self.last_update_time).as_millis() as u64;

        // delta_t is more than the window size, reset the whole limiter
        if delta_t >= W as u64 {
            self.last_update_time = now;
            self.window_buffer.fill(0);
            self.window_buffer[0] = tokens;
            return Ok(());
        }

        if delta_t != 0 {
            self.last_update_time = now;
            // Time has moved on, shift existing items right for delta_t slots
            let move_range = 0..(W - delta_t as usize);
            self.window_buffer.copy_within(move_range, delta_t as usize);

            // Zero all slots that were not updated
            self.window_buffer[..delta_t as usize].fill(0);
        }

        // Too many tokens used during the window?
        let tokens_left = self.config.capacity - self.window_buffer.iter().sum::<u64>();
        if tokens_left >= tokens {
            // Add tokens to current timeslot
            self.window_buffer[0] += tokens;
            Ok(())
        } else {
            Err(CantConsume)
        }
    }
}

/// Sliding window counter -type rate limiter
///
/// A sliding window counter can be described as a more
/// performant but less accurate approximation for [`SlidingWindowLog`].
///
/// The timeline is split into fixed windows of defined
/// size and then an approximated moving window limit
/// can be calculated by adding up the tokens used from
/// the current window with tokens from the previous window
/// multiplied by the virtual "moving window" overlap
/// ratio.
///
/// If we had a situation like this, and tried to consume
/// tokens(s) at time `t = 15`:
///
/// ```text
/// t=0                  10                 20
/// |--- Window N - 1 ---|---  Window N  ---|--->
/// |    100 tokens      |     50 tokens    |
/// |--------------------|------------------|--->
///          |--- Sliding window ---|
///          |----------------------|
///                                t=15
/// ```
///
/// We would calculate the amount of tokens used during this
/// virtual "sliding window" by taking into account tokens
/// from the previous `N - 1` window with a factor of `0.5`
/// since that is the overlap ratio of our sliding window.
///
/// Effective tokens used during this sliding window would be:
/// `100 * 0.5 + 50 = 100`
///
/// If our window capacity was configured to be 100 or less,
/// this consume would not be possible at this time.
pub struct SlidingWindowCounter<T>
where
    T: Fn() -> Duration,
{
    config: SlidingWindowConfig<T>,
    tokens_prev: u64,
    tokens_this: u64,
    window_index: u64,
    window_width_ms: u64,
    start_time: Duration,
}

impl<T> SlidingWindowCounter<T>
where
    T: Fn() -> Duration,
{
    /// Initialize a new sliding window limiter utilizing the given timer
    ///
    /// # Arguments
    /// * `capacity` - how many consumes are allowed during a single window
    /// * `window_width_ms` - window width in milliseconds
    /// * `time_provider_t` - closure that returns a monotonically nondecreasing
    ///   timestamp as [`Duration`] from some fixed epoch in the past
    ///
    /// # Notes
    /// * If you are developing for a `std` target, you probably wish to use [`sliding_window_counter`]
    /// * Window width is defined by the generic argument `W: usize`
    pub fn new_with_time_provider(capacity: u64, window_width_ms: u64, time_provider: T) -> Self {
        let time_now = time_provider();
        let config = SlidingWindowConfig::new(capacity, time_provider);
        Self {
            config,
            window_index: 0,
            tokens_prev: 0,
            tokens_this: 0,
            window_width_ms,
            start_time: time_now,
        }
    }
}

impl<T> Limiter for SlidingWindowCounter<T>
where
    T: Fn() -> Duration,
{
    fn try_consume(&mut self, tokens: u64) -> LimiterResult {
        // Get current window index
        let now = (self.config.time_provider)();
        let delta_t = now.saturating_sub(self.start_time).as_millis() as f64;
        let index_float = delta_t / self.window_width_ms as f64;

        let index = index_float.trunc() as u64;
        let overlap = index_float.fract();

        if index == (self.window_index + 1) {
            // Moved on to next window, move current tokens to previous window
            self.tokens_prev = self.tokens_this;
            self.tokens_this = 0;
            self.window_index = index;
        } else if index >= (self.window_index + 2) {
            // We skipped at least one full window, zero counters
            self.tokens_prev = 0;
            self.tokens_this = 0;
            self.window_index = index;
        }

        // Take tokens from previous window into account according to the overlap
        let effective_tokens_previous = (self.tokens_prev as f64 * (1.0 - overlap)) as u64;
        if (effective_tokens_previous + self.tokens_this + tokens) > self.config.capacity {
            Err(CantConsume)
        } else {
            self.tokens_this += tokens;
            Ok(())
        }
    }
}

/// Configuration for a fixed window limiter
#[derive(Clone, Copy)]
struct SlidingWindowConfig<T>
where
    T: Fn() -> Duration,
{
    capacity: u64,
    time_provider: T,
}

impl<T: Fn() -> Duration> SlidingWindowConfig<T> {
    fn new(capacity: u64, time_provider: T) -> Self {
        Self {
            capacity,
            time_provider,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{mock_assets::MockClock, Limiter, SlidingWindowCounter, SlidingWindowLog};

    #[test]
    fn verify_rate_sliding() {
        let clock = MockClock::new();
        // Each call steps the clock 1ms forward
        let mut w = SlidingWindowLog::<_, 10>::new_with_time_provider(1000, || clock.step(1000));

        // T = 1ms, tokens left = 1000
        assert!(w.try_consume(500).is_ok());
        // T = 2ms, tokens left = 500
        assert!(w.try_consume(500).is_ok());
        // T = 3ms, tokens left = 0
        assert!(w.try_consume_one().is_err());
        // T = 4ms, tokens left = 0
        assert!(w.try_consume_one().is_err());
        // T = 5ms, tokens left = 0
        assert!(w.try_consume_one().is_err());
        // T = 6ms, tokens left = 0
        assert!(w.try_consume_one().is_err());
        // T = 7ms, tokens left = 0
        assert!(w.try_consume_one().is_err());
        // T = 8ms, tokens left = 0
        assert!(w.try_consume_one().is_err());
        // T = 9ms, tokens left = 0
        assert!(w.try_consume_one().is_err());
        // T = 10ms, tokens left = 0
        assert!(w.try_consume_one().is_err());
        // T = 11ms, tokens left = 500
        assert!(w.try_consume_one().is_ok());
        // T = 12ms, tokens left = 999
        assert!(w.try_consume(999).is_ok());
        // T = 13ms, tokens left = 0
        assert!(w.try_consume_one().is_err());
    }

    #[test]
    fn verify_rate_sliding_counter() {
        let clock = MockClock::new();
        // Each call steps the clock 1ms forward
        let mut w = SlidingWindowCounter::new_with_time_provider(1000, 10, || clock.step(1000));

        // First window
        // T = 1ms, tokens left = 1000
        assert!(w.try_consume(1000).is_ok());
        // T = 2ms, tokens left = 0
        assert!(w.try_consume_one().is_err());
        // T = 3ms, tokens left = 0
        assert!(w.try_consume_one().is_err());
        // T = 4ms, tokens left = 0
        assert!(w.try_consume_one().is_err());
        // T = 5ms, tokens left = 0
        assert!(w.try_consume_one().is_err());
        // T = 6ms, tokens left = 0
        assert!(w.try_consume_one().is_err());
        // T = 7ms, tokens left = 0
        assert!(w.try_consume_one().is_err());
        // T = 8ms, tokens left = 0
        assert!(w.try_consume_one().is_err());
        // T = 9ms, tokens left = 0
        assert!(w.try_consume_one().is_err());
        // T = 10ms, tokens left = 0
        assert!(w.try_consume_one().is_err());
        // Second
        // T = 11ms, effective tokens used by previous window = 0.10.. * 1000 = 899
        assert!(w.try_consume(101).is_ok());
        // T = 12ms, effective tokens used by previous window = 0.199.. * 1000 = 800
        // tokens used by this window = 101
        // total left = 99
        assert!(w.try_consume(99).is_ok());

        // T = 12ms, effective tokens used by previous window = 0.30.. * 1000 = 700
        // tokens used by this window = 200
        // total left = 100
        assert!(w.try_consume(101).is_err());
    }
}
