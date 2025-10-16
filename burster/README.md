# Burster ⏩

[![Crates.io Version](https://img.shields.io/crates/v/burster?style=flat-square)](https://crates.io/crates/burster)
[![docs.rs](https://img.shields.io/docsrs/burster?style=flat-square)](https://docs.rs/burster/latest/burster/)


Burster is a high quality and lightweigh crate providing stack allocated rate limiters with minimal dependencies.
Guaranteed to work on `no_std` targets, but also comfortable on standard targets.

## Supported rate limiter types

- Token bucket
- Fixed window
- Sliding window log
- Sliding window counter
- ..something else? Make a request or open a PR :)

## Usage

On `std` targets usage is simple. Install the crate with default features enabled and
you'll get access to straightforward utility functions for instantiating limiters.

```rust
// Instantiate a token bucket that allowes an average consume
// rate of 100 tokens per second and with bucket_size = 10
let mut bucket = burster::token_bucket(100, 10);

// Use the bucket:
if bucket.try_consume_one().is_ok() {
    // All good, enough tokens left
} else {
    // Not enough tokens for this consume
}
```

On `no_std` targets you'll have to install the crate with default features disabled and
provide bindings to your platforms clock functionality in the form of a closure that returns
the current timestamp as `Duration` from some fixed epoch in the past.

```rust
// Instantiate a token bucket that allowes an average consume
// rate of 100 tokens per second and with bucket_size = 10
let mut bucket = burster::TokenBucket::new_with_time_provider(100, 10, || {
    // Return current timestamp
    Duration::from_micros(get_platform_micros_from_boot())
});
```
