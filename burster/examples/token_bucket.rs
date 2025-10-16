use burster::Limiter;
use rand::Rng;
use std::{
    thread,
    time::{Duration, Instant},
};

fn main() {
    // Set up the bucket to allow 100 consumer per second, with minor burstiness (capacity = 10)
    let mut bucket = burster::token_bucket(100, 10);

    let start = Instant::now();
    let mut pass = 0;
    let mut rng = rand::thread_rng();

    println!("Trying to consume 100 000 tokens with varying intervals");
    for _ in 0..100_000 {
        if bucket.try_consume_one().is_ok() {
            pass += 1
        }
        thread::sleep(Duration::from_micros(rng.gen_range(0..10)));
    }

    // Resulting rate should be around 100/s.
    // There can be some variation since this is not a perfect simulation.
    let elapsed = start.elapsed().as_secs_f64();
    let rate_per_s = pass as f64 / elapsed;
    println!("Average pass rate {rate_per_s}");
}
