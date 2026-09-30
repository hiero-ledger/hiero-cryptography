// SPDX-License-Identifier: Apache-2.0

//! Wall-clock timing of hinTS aggregation and verification, for comparing revisions.
//!
//! Ignored by default. Run it from the crate directory with
//!
//!     cargo test --release timing -- --ignored --nocapture --test-threads=1
//!
//! It only touches the public API, so the same file can be dropped into any revision of
//! the crate. Building each universe costs O(n^2) work per party (hint generation and hint
//! verification), which is what caps the sizes below.

use std::time::{Duration, Instant};

use ark_std::collections::HashMap;

use crate::hints::{serialize, ExtendedPublicKey, HinTS, PartialSignature, Weight, F};
use crate::setup::PowersOfTauProtocol;

const SIZES: [usize; 4] = [16, 32, 64, 128];
const RUNS: usize = 10;

/// runs `op` once untimed, then `RUNS` times timed; returns the fastest and the mean run
fn time<T>(mut op: impl FnMut() -> T) -> (Duration, Duration) {
    std::hint::black_box(op());
    let mut runs = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        let start = Instant::now();
        let result = op();
        runs.push(start.elapsed());
        std::hint::black_box(result);
    }
    let fastest = *runs.iter().min().unwrap();
    let mean = runs.iter().sum::<Duration>() / RUNS as u32;
    (fastest, mean)
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

#[test]
#[ignore]
fn timing_aggregate_and_verify() {
    let msg = b"hinTS timing";
    let threshold = (F::from(1), F::from(3));

    println!("| n | signers | aggregate fastest / mean (ms) | verify fastest / mean (ms) | signature bytes |");
    println!("|---|---|---|---|---|");
    for n in SIZES {
        let (crs, _proof) =
            PowersOfTauProtocol::contribute(&PowersOfTauProtocol::init(n), [7u8; 32]).unwrap();
        let sks: Vec<_> = (0..n - 1)
            .map(|i| HinTS::keygen([i as u8 + 1; 32]).unwrap())
            .collect();
        let signer_info: HashMap<usize, (Weight, ExtendedPublicKey)> = (0..n - 1)
            .map(|i| (i, (F::from(1 + i as u64), HinTS::hint_gen(&crs, n, i, &sks[i]).unwrap())))
            .collect();
        let (vk, ak) = HinTS::preprocess(n, &crs, &signer_info).unwrap();

        // three in four parties sign
        let sigs: HashMap<usize, PartialSignature> = (0..n - 1)
            .filter(|i| i % 4 != 3)
            .map(|i| (i, HinTS::sign(msg, &sks[i]).unwrap()))
            .collect();

        let (aggregate_fastest, aggregate_mean) =
            time(|| HinTS::aggregate(&crs, &ak, &vk, &sigs).unwrap());
        let π = HinTS::aggregate(&crs, &ak, &vk, &sigs).unwrap();
        // assert inside the timed closure, so a verifier that bails out early cannot pass
        // for a fast one
        let (verify_fastest, verify_mean) =
            time(|| assert!(HinTS::verify(msg, &vk, &π, threshold).unwrap()));

        println!(
            "| {} | {} | {:.1} / {:.1} | {:.2} / {:.2} | {} |",
            n,
            sigs.len(),
            ms(aggregate_fastest),
            ms(aggregate_mean),
            ms(verify_fastest),
            ms(verify_mean),
            serialize(&π).unwrap().len()
        );
    }
}
