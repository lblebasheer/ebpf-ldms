//! # Burster
//!
//! Burster is a lightweigh crate providing stack allocated rate limiters
//! with minimal dependencies.
//!
//! ## Available limiters
//!
//! * [`TokenBucket`] - basic token bucket type limiter
//! * [`FixedWindow`] - fixed window type limiter
//! * [`SlidingWindowLog`] - sliding window type limiter
//! * [`SlidingWindowCounter`] - sliding window counter type limiter (an approximation of [`SlidingWindowLog`])
//!
//! ## Platform support
//!
//! On `std` targets you are all good to go and can use the following utility
//! functions for instantiating the limiters:
//!
//! * [`token_bucket`]
//! * [`fixed_window`]
//! * [`sliding_window_log`]
//! * [`sliding_window_counter`]
//!
//! On `no_std` targets you'll have to provide bindings to your platforms timing
//! functionalities and use the constructor methods:
//!
//! * [`TokenBucket::new_with_time_provider`]
//! * [`FixedWindow::new_with_time_provider`]
//! * [`SlidingWindowLog::new_with_time_provider`]
//! * [`SlidingWindowCounter::new_with_time_provider`]
//!
//! You must provide timer access in the form of a closuse that returns current system
//! timestamp as a [`core::time::Duration`] from some fixed epoch in the past.
//! It's a bit silly, but we use `Duration` instead of `Instant` because `Instant` requires `std`.

// Support no_std
#![cfg_attr(not(feature = "std"), no_std)]

mod fixed_window_impl;
mod sliding_window_impl;
mod token_bucket_impl;

use core::fmt;

#[cfg(feature = "std")]
pub use token_bucket_impl::token_bucket;
pub use token_bucket_impl::TokenBucket;

#[cfg(feature = "std")]
pub use fixed_window_impl::fixed_window;
pub use fixed_window_impl::FixedWindow;

#[cfg(feature = "std")]
pub use sliding_window_impl::{sliding_window_counter, sliding_window_log};
pub use sliding_window_impl::{SlidingWindowCounter, SlidingWindowLog};

/// Common trait for all rate limiter implementations
pub trait Limiter {
    /// Try to consume tokens
    ///
    /// # Arguments
    /// * `tokens` - how many tokens to consume
    ///
    /// # Returns
    /// * `Ok(())` - token consumed
    /// * `Err(CantConsume)` - not enough tokens left for this time window
    fn try_consume(&mut self, tokens: u64) -> LimiterResult;

    /// Try to consume a single token
    ///
    /// # Returns
    /// * `Ok(())` - token consumed
    /// * `Err(CantConsume)` - not enough tokens left for this time window
    fn try_consume_one(&mut self) -> LimiterResult {
        self.try_consume(1)
    }
}

/// Error type indicating that the requested amount of
/// tokens cannot be consumed from the limiter.
///
/// I.e. the limiter *limits*
#[derive(Debug)]
pub struct CantConsume;

impl fmt::Display for CantConsume {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Can't consume from limiter")
    }
}

// core::error::Error trait stabilised at release 1.81
#[rustversion::since(1.81)]
impl core::error::Error for CantConsume {}

/// Limiter consume action result type
///
/// There are no actual errors that can be returned,
/// and the error type here is only used for signalling
/// that the requested amount of tokens cannot be consumed.
pub type LimiterResult = Result<(), CantConsume>;

#[cfg(feature = "std")]
mod macros {
    macro_rules! std_time_provider {
        () => {
            || {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("Time went backwards")
            }
        };
    }

    pub(crate) use std_time_provider;
}

#[cfg(test)]
pub(crate) mod mock_assets {
    use core::{
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };

    pub struct MockClock(AtomicU64);

    impl MockClock {
        pub fn new() -> Self {
            Self(AtomicU64::new(0))
        }

        pub fn step(&self, step: u64) -> Duration {
            Duration::from_micros(self.0.fetch_add(step, Ordering::Relaxed))
        }
    }
}
