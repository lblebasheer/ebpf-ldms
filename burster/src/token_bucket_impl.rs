//! Token bucket -type limiter

use core::time::Duration;

#[cfg(feature = "std")]
use crate::macros::std_time_provider;
use crate::{CantConsume, Limiter, LimiterResult};

/// Build a token bucket limiter
///
/// # Arguments
/// * `rate_per_sec` - how many consumes should be allowed per second on average
/// * `capacity` - bucket capacity to dictate the burstiness of this limiter
#[cfg(feature = "std")]
pub fn token_bucket(rate_per_s: u64, capacity: u64) -> TokenBucket<impl Fn() -> Duration> {
    TokenBucket::new_with_time_provider(rate_per_s, capacity, std_time_provider!())
}

/// Token bucket -type rate limiter
///
/// A token bucket limiter can be illustrated as a being filled
/// with tokens at a constant rate, while consumes will remove
/// tokens from the bucket.
///
/// This leads to a soft limiter where occasional burstiness is
/// allowed since as long as the bucket holds tokens those can
/// be consumed at an unlimited rate. Ultimately the bucket size
/// is what defined the burstiness.
pub struct TokenBucket<T>
where
    T: Fn() -> Duration,
{
    config: TokenBucketConfig<T>,
    tokens: u64,
    last_update_t: Duration,
}

impl<T> TokenBucket<T>
where
    T: Fn() -> Duration,
{
    /// Initialize a new token bucket utilizing the given timer
    ///
    /// # Arguments
    /// * `rate_per_sec` - how many consumes should be allowed per second on average
    /// * `capacity` - bucket capacity to dictate the burstiness of this limiter
    /// * `time_provider_t` - closure that returns a monotonically nondecreasing
    ///   timestamp as [`Duration`] from some fixed epoch in the past
    ///
    /// If you are developing for a `std` target, you probably wish to use [`token_bucket`]
    pub fn new_with_time_provider(rate_per_s: u64, capacity: u64, time_provider: T) -> Self {
        let time_now = time_provider();
        let config = TokenBucketConfig::new(capacity, rate_per_s, time_provider);
        Self {
            config,
            tokens: capacity,
            last_update_t: time_now,
        }
    }
}

impl<T> Limiter for TokenBucket<T>
where
    T: Fn() -> Duration,
{
    fn try_consume(&mut self, tokens: u64) -> LimiterResult {
        // First, get elapsed time since last call
        let now = (self.config.time_provider)();
        let delta_t = now.saturating_sub(self.last_update_t);
        let tokens_to_add = (delta_t.as_secs_f64() * self.config.rate_per_s) as u64;

        // If the tokens to add rounds down to zero, lets not update
        // the timestamp so we don't lose any accumulated tokens due
        // to rounding inaccuracies.
        if tokens_to_add != 0 {
            self.last_update_t = now;
            self.tokens = (self.tokens.saturating_add(tokens_to_add)).min(self.config.capacity);
        }

        // Take away tokens, if possible
        if self.tokens >= tokens {
            self.tokens -= tokens;
            Ok(())
        } else {
            Err(CantConsume)
        }
    }
}

/// Configuration for a token bucket
#[derive(Clone, Copy)]
struct TokenBucketConfig<T>
where
    T: Fn() -> Duration,
{
    capacity: u64,
    rate_per_s: f64,
    time_provider: T,
}

impl<T: Fn() -> Duration> TokenBucketConfig<T> {
    fn new(capacity: u64, rate_per_s: u64, time_provider: T) -> Self {
        Self {
            capacity,
            rate_per_s: rate_per_s as f64,
            time_provider,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{mock_assets::MockClock, Limiter};

    use super::TokenBucket;

    #[test]
    fn verify_rate() {
        let clock = MockClock::new();
        // Each call steps the clock 100us forward
        let mut b = TokenBucket::new_with_time_provider(1000, 100, || clock.step(100));

        // Can consume at rate of 100 tokens / 100 us because the bucket is full
        // T = 100us, tokens = 100
        assert!(b.try_consume(100).is_ok());

        // T = 200us, tokens = 0
        assert!(b.try_consume(1).is_err());
        // T = 300us, tokens = 0
        assert!(b.try_consume(1).is_err());
        // T = 400us, tokens = 0
        assert!(b.try_consume(1).is_err());
        // T = 500us, tokens = 0
        assert!(b.try_consume(1).is_err());
        // T = 600us, tokens = 0
        assert!(b.try_consume(1).is_err());
        // T = 700us, tokens = 0
        assert!(b.try_consume(1).is_err());
        // T = 800us, tokens = 0
        assert!(b.try_consume(1).is_err());
        // T = 900us, tokens = 0
        assert!(b.try_consume(1).is_err());
        // T = 1ms, tokens = 1
        assert!(b.try_consume(1).is_ok());
        // T = 1100us, tokens = 0
        assert!(b.try_consume(1).is_err());
    }
}
