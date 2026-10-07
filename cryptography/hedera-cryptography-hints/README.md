# hedera-cryptography-hints

Weighted threshold signatures with silent setup over BLS12-381, implementing
[hinTS](https://eprint.iacr.org/2023/567). The scheme lives in `src/main/rust`;
`HintsLibraryBridge` exposes it to Java over JNI.

## Conventions

- `n` is the domain size: the number of parties plus one (for the reserved slot), rounded up
  to the nearest power of two. So 31 parties give `n` = 32, and 32 parties give `n` = 64.
  The Java bridge requires `n <= MAX_SIGNERS_NUM`.
- Party ids run from 0 to `n − 2`; the scheme reserves slot `n − 1`.
- A hint is bound to its `(n, id)`; if either changes, the party computes a new one.
- `verify` passes iff the signers' weight is strictly greater than `num/den` of the total.

## CRS setup

A powers-of-tau ceremony ([ePrint 2022/1592](https://eprint.iacr.org/2022/1592)), run once
per `n` (see *Network size and τ*).

| Step | Who | Rust (`PowersOfTauProtocol::`) | Java (`HintsLibraryBridge`) |
|---|---|---|---|
| 1 | anyone | `init(d)`, with `d ≥ n` | `initCRS(d)` |
| 2 | each contributor, in turn | `contribute(&prev, seed)` → `(next, proof)` | `updateCRS(prev, seed)` → `next ‖ proof` (proof = last 128 bytes) |
| 3 | every node, every step | `verify_contribution(&prev, &next, &proof)` | `verifyCRS(prev, next, proof)` |
| 4 | anyone, optional | `prune_crs(&crs, n)` | `pruneCRS(crs, n)` |

`init` is the CRS for τ = 1 and must not be used as is. The CRS to use is the last link of a
chain that starts at `init(d)` and verifies at every step. Each contributor draws a fresh
32-byte seed and destroys it afterwards.

## Typical execution

Steps 1–4 run once per roster, steps 5–8 once per message.

| Step | Who | Rust (`HinTS::`) | Java (`HintsLibraryBridge`) |
|---|---|---|---|
| 1 | each party | `keygen(seed)` → `sk` | `generateSecretKey(seed)` |
| 2 | each party `i` | `hint_gen(&crs, n, i, &sk)` → hint, published | `computeHints(crs, sk, i, n)` |
| 3 | every node, per hint | `verify_hint(&crs, n, i, &hint)`; drop failures | `validateHintsKey(crs, hint, i, n)` |
| 4 | every node | `preprocess(n, &crs, &signers)` → `(vk, ak)`; `signers` maps `i → (w_i, hint_i)` | `preprocess(crs, ids, hints, weights, n)` |
| 5 | each signer | `sign(msg, &sk)` → `σ_i` | `signBls(msg, sk)` |
| 6 | aggregator | `partial_verify(msg, &ak, i, &σ_i)` or `partial_verify_batch`; drop failures | `verifyBls` / `verifyBlsBatch` |
| 7 | aggregator | `aggregate(&crs, &ak, &vk, &sigs)` → `π`; `sigs` maps `i → σ_i` | `aggregateSignatures(crs, ak, vk, ids, sigs)` |
| 8 | verifier | `verify(msg, &vk, &π, (num, den))` | `verifyAggregate(π, msg, vk, num, den)`; the 3-arg form uses 1/2 |

`preprocess` is deterministic, so nodes with the same inputs derive the same keys;
`aggregate` is too, so one signer set yields one `π`. A verifier needs only `vk` (1096
bytes), `msg` and `π` (1248 bytes). `it_works` in `hints.rs` runs this sequence in Rust;
`HintsLibraryBridgeTest` runs it through Java.

## Assumptions

The library supplies a check for everything other parties send (`verify_contribution`,
`verify_hint`, `partial_verify`, `verify`). The JNI layer rejects points that are off the
curve or outside the subgroup when deserializing; Rust callers must deserialize with
validation too (no `*_unchecked`). The caller is trusted to run these checks and to supply
everything else.

**Unforgeability** holds only if the caller:

- **Uses a sound CRS:** at least one honest contributor, and the whole chain checked with
  `verify_contribution`. The hinTS functions check only the CRS's length.
- **Gets `vk` from a trusted source:** `verify` checks only that `vk.n` is a power of two.
  Derive `vk` with `preprocess` from authentic inputs, or take it from a source you trust.
- **Feeds `preprocess` authentic inputs:** `verify_hint` proves a hint is well formed for its
  own public key and that its sender knows the secret key, not that the key belongs to party
  `i`. Binding hints and weights to node identities is the caller's job.
- **Keeps weights and threshold in range:** the threshold comparison runs on field elements
  and is meaningful only for non-negative weights totalling less than 2^63 and positive
  `num`, `den`. The Java bridge enforces this; the Rust API does not.
- **Uses fresh, secret seeds:** `keygen` and `contribute` are deterministic in their seeds.
  `SecretKey` is zeroized on drop; serialized key bytes held by the caller are not.
- **Runs a fresh ceremony whenever `n` changes** (below).

The aggregator and `ak` need not be trusted for unforgeability: `verify` depends only on
`vk`. Producing a signature that verifies additionally requires the caller to:

- **Filter hints before `preprocess`:** one invalid hint fails the whole call (the paper
  instead zeroes that party's weight).
- **Verify partial signatures before `aggregate`:** `aggregate` does not, so one bad partial
  signature yields a `π` that fails `verify`.
- **Pass matching inputs:** `ak` and `vk` from the same `preprocess` run, over the same CRS.
- **Reset the JNI caches:** the bridge caches the first CRS and aggregation key it
  deserializes and ignores the bytes passed on later calls. Call `resetCache()` whenever
  either changes, and never use two of either concurrently.

## Network size and τ

Whenever a roster change moves `n`, in either direction, run the ceremony again from `init`.
For example, 31 → 32 parties takes `n` from 32 to 64, and 32 → 31 takes it back to 32. The
new run yields a CRS whose τ is independent of the old one. Every party then computes new
hints against the new CRS, and `preprocess` runs again. Rosters with the same `n` may keep
the CRS. Never carry a CRS over to a new `n`, whatever its degree: pruning or reusing it
keeps the old τ.

Why: a hint for size `n` publishes [sk·f(τ)]₁ for polynomials f up to degree n − 1 (e.g.
sk·(L_i(τ) − L_i(0))). Unforgeability in a universe of size m rests on the degree check
(paper, Lemma 4), which requires that no such element for an honest key has deg f ≥ m. Under
a shared τ, an honest party's hint for a larger size violates this, and signatures under the
smaller universe's `vk` become forgeable: the new universe when shrinking, the old one when
growing (which matters as long as anything still accepts the old `vk`). §6.1 of the paper
("HintGen without size n and index i") notes this and the fix. The attack combines one key's
hints for two sizes under one τ, so a fresh ceremony per size rules it out whether or not
parties rotate their BLS keys.
