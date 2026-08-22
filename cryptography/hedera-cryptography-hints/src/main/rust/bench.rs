// SPDX-License-Identifier: Apache-2.0

//! Timing and proof-size harness for hinTS signature aggregation and verification.
//!
//! These are `#[ignore]`d tests rather than `#[bench]`es so that they run on the stable
//! toolchain without pulling in a benchmarking dependency. Run them with:
//!
//! ```text
//! cargo test --release -- --ignored --nocapture --test-threads=1 hints_bench
//! ```
//!
//! `--test-threads=1` matters: the harness tests would otherwise contend for cores and
//! report inflated times.
//!
//! The harness quantifies the effect of the quotient-merging optimization from §3.4.3 of
//! the whitepaper: it reports wall-clock time for `aggregate` / `verify` and the serialized
//! size of the aggregate signature across a range of universe sizes. Every measured
//! `verify` is asserted to return `true`, so a regression cannot masquerade as a speed-up
//! by making verification bail out early.

use std::time::{Duration, Instant};

use ark_serialize::CanonicalSerialize;
use ark_std::collections::HashMap;
use rand::Rng;

use crate::hints::{
    serialize, AggregationKey, ExtendedPublicKey, HinTS, PartialSignature, SecretKey,
    VerificationKey, Weight, CRS, F,
};
use crate::setup::PowersOfTauProtocol;

/// Universe sizes to measure. Each must be a power of two. Fixture construction costs
/// O(n^2) pairings (one `verify_hint` per party, each linear in n), so the largest entry
/// dominates the runtime of the harness.
const UNIVERSE_SIZES: &[usize] = &[16, 32, 64, 128];

/// Fraction of the n-1 real parties that contribute a partial signature.
const PARTICIPATION: f64 = 0.75;

/// Timed iterations per data point.
const ITERATIONS: usize = 20;

/// Untimed iterations run before timing starts, to warm caches and the allocator.
const WARMUP: usize = 3;

/// Threshold the benchmarked signatures are verified against.
const THRESHOLD: (u64, u64) = (1, 3);

/// Summary statistics for a timed operation. `min` is the more stable statistic for
/// short-running operations; `mean` is reported alongside it to expose variance.
struct Timing {
    min: Duration,
    mean: Duration,
}

impl Timing {
    /// Runs `op` `WARMUP` times untimed, then `ITERATIONS` times timed.
    fn measure<T>(mut op: impl FnMut() -> T) -> Timing {
        for _ in 0..WARMUP {
            op();
        }

        let mut total = Duration::ZERO;
        let mut min = Duration::MAX;
        for _ in 0..ITERATIONS {
            let start = Instant::now();
            let result = op();
            let elapsed = start.elapsed();
            // keep the result alive until after the clock is read, so that the optimizer
            // cannot sink any part of `op` past the measurement
            std::hint::black_box(result);

            total += elapsed;
            min = min.min(elapsed);
        }

        Timing { min, mean: total / ITERATIONS as u32 }
    }
}

/// Everything needed to aggregate and verify repeatedly for one universe size.
struct Fixture {
    n: usize,
    crs: CRS,
    ak: AggregationKey,
    vk: VerificationKey,
    partial_signatures: HashMap<usize, PartialSignature>,
    /// wall-clock time spent in `preprocess`, reported for context
    preprocess: Duration,
}

impl Fixture {
    fn new(n: usize, msg: &[u8]) -> Fixture {
        let num_signers = n - 1;

        // one-time SRS. WARN: a fixed seed is fine here only because this is a benchmark.
        let init_crs = PowersOfTauProtocol::init(n);
        let (crs, proof) = PowersOfTauProtocol::contribute(&init_crs, [86u8; 32]).unwrap();
        assert!(PowersOfTauProtocol::verify_contribution(&init_crs, &crs, &proof));

        // distinct key per party, deterministically derived from the index
        let sks: Vec<SecretKey> = (0..num_signers)
            .map(|i| {
                let mut seed = [0u8; 32];
                seed[0] = (i & 0xff) as u8;
                seed[1] = ((i >> 8) & 0xff) as u8;
                HinTS::keygen(seed).unwrap()
            })
            .collect();

        let epks: Vec<ExtendedPublicKey> = (0..num_signers)
            .map(|i| HinTS::hint_gen(&crs, n, i, &sks[i]).unwrap())
            .collect();

        let rng = &mut ark_std::test_rng();
        let weights: Vec<Weight> =
            (0..num_signers).map(|_| F::from(rng.gen_range(1..10)) + F::from(10)).collect();

        let signer_info: HashMap<usize, (Weight, ExtendedPublicKey)> =
            (0..num_signers).map(|i| (i, (weights[i], epks[i].clone()))).collect();

        let start = Instant::now();
        let (vk, ak) = HinTS::preprocess(n, &crs, &signer_info).unwrap();
        let preprocess = start.elapsed();

        // a random subset of the parties signs
        let mut partial_signatures = HashMap::new();
        for i in 0..num_signers {
            if rng.gen_bool(PARTICIPATION) {
                partial_signatures.insert(i, HinTS::sign(msg, &sks[i]).unwrap());
            }
        }

        Fixture { n, crs, ak, vk, partial_signatures, preprocess }
    }
}

fn threshold() -> (F, F) {
    (F::from(THRESHOLD.0), F::from(THRESHOLD.1))
}

/// Reports `aggregate` / `verify` timings and aggregate-signature sizes per universe size.
#[test]
#[ignore = "benchmark; run with: cargo test --release -- --ignored --nocapture hints_bench"]
fn hints_bench_aggregate_verify() {
    let msg = b"hinTS benchmark message";
    let threshold = threshold();

    println!();
    println!("hinTS aggregate / verify, {} iterations after {} warmup", ITERATIONS, WARMUP);
    println!();
    println!(
        "| n | signers | preprocess (ms) | aggregate min (ms) | aggregate mean (ms) \
         | verify min (ms) | verify mean (ms) | sig bytes (uncompressed) | sig bytes (compressed) |"
    );
    println!(
        "| --: | --: | --: | --: | --: | --: | --: | --: | --: |"
    );

    for &n in UNIVERSE_SIZES {
        let f = Fixture::new(n, msg);

        let aggregate = Timing::measure(|| {
            HinTS::aggregate(&f.crs, &f.ak, &f.vk, &f.partial_signatures).unwrap()
        });

        let π = HinTS::aggregate(&f.crs, &f.ak, &f.vk, &f.partial_signatures).unwrap();
        assert!(
            HinTS::verify(msg, &f.vk, &π, threshold).unwrap(),
            "benchmarked signature must verify for n = {}",
            n
        );

        let verify = Timing::measure(|| {
            assert!(HinTS::verify(msg, &f.vk, &π, threshold).unwrap());
        });

        println!(
            "| {} | {} | {:.1} | {:.3} | {:.3} | {:.3} | {:.3} | {} | {} |",
            f.n,
            f.partial_signatures.len(),
            f.preprocess.as_secs_f64() * 1e3,
            aggregate.min.as_secs_f64() * 1e3,
            aggregate.mean.as_secs_f64() * 1e3,
            verify.min.as_secs_f64() * 1e3,
            verify.mean.as_secs_f64() * 1e3,
            serialize(&π).unwrap().len(),
            π.compressed_size(),
        );
    }
    println!();
}

/// Reports the aggregate-signature size, which is constant in n, in both encodings.
/// This is the figure the quotient-merging optimization moves most directly.
#[test]
#[ignore = "benchmark; run with: cargo test --release -- --ignored --nocapture hints_bench"]
fn hints_bench_signature_size() {
    let msg = b"hinTS benchmark message";
    let f = Fixture::new(32, msg);
    let π = HinTS::aggregate(&f.crs, &f.ak, &f.vk, &f.partial_signatures).unwrap();
    assert!(HinTS::verify(msg, &f.vk, &π, threshold()).unwrap());

    // BLS12-381 element widths under ark-serialize, for reading the totals below
    const G1_UNCOMPRESSED: usize = 96;
    const G1_COMPRESSED: usize = 48;
    const G2_UNCOMPRESSED: usize = 192;
    const G2_COMPRESSED: usize = 96;
    const F_BYTES: usize = 32;

    println!();
    println!("hinTS aggregate signature size (constant in n)");
    println!(
        "  uncompressed: {} bytes   (this is what the JNI boundary ships)",
        serialize(&π).unwrap().len()
    );
    println!("  compressed:   {} bytes", π.compressed_size());
    println!(
        "  element widths: G1 {}/{}, G2 {}/{}, F {} (uncompressed/compressed)",
        G1_UNCOMPRESSED, G1_COMPRESSED, G2_UNCOMPRESSED, G2_COMPRESSED, F_BYTES
    );
    println!("  layout: 9 G1 + 1 G2 + 6 F; asserted by hints::tests::test_serialization");
    println!();
}
