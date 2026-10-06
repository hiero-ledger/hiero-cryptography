# novawraps

Address-book rotation attested by a weighted Schnorr multisignature, folded with
[Nova](https://github.com/microsoft/Nova).

Incrementally verifiable computation (IVC) lets a prover extend a proof with each
computation step so that the resulting proof attests to the correctness of every
step so far (see the [Nova paper](https://eprint.iacr.org/2021/370)).

A committee is an *address book*: up to `MAX_AB_SIZE` entries of
`(node id, (public key, proof of knowledge), weight)`. Rotating the committee means
producing a new address book that the outgoing one has jointly signed, and IVC
maintains a proof that every rotation since genesis was authorised that way — without a
verifier ever seeing an intermediate book or signature.

Nonidentity public keys must be unique within an address book, regardless of node ID,
weight, or proof of possession. Sentinel keys may repeat. Selected sentinel seats
are omitted from signing rounds, so they require no commitments, nonces, or shares.

Each member's `Weight` is a `u64`. The total effective committee weight must also fit
in a `u64`; larger totals are rejected. A strict majority is checked as
`signing_weight > total_weight / 2`, using integer division without doubling the sum.
Identity seats contribute zero to both sums. The circuit constrains every stored weight
and the effective total to 64 bits.

Weights now serialize as 8-byte integers instead of field elements. Address-book hashes
for previously valid 64-bit weights are unchanged. The added circuit range constraints
require regenerating public parameters, prover/verifier keys, and proofs; existing
powers-of-tau files can be reused.

Use `WRAPS` with the public address-book, signing, and key types.
Proofs, serialized verification keys, rotation messages, and signing-round messages use
`Vec<u8>` for transport. Verifier setup derives a retained `CompressedVerifyingKey`
from public parameters; verification borrows that prepared object.
Padding, signing-subset selection, and the underlying cryptographic helpers are
internal implementation details, outside the public API.

## Ledger ID

A ledger ID is the byte array returned by `WRAPS::compute_rotation_message` for the
genesis address book and genesis hints verification key:

```rust
let ledger_id: Vec<u8> = WRAPS::compute_rotation_message(&genesis_ab, &genesis_hints_vk)?;
```

It encodes `[H(genesis_ab), H(genesis_hints_vk)]` as a `RotationMessage<E2>`.
Retain these bytes across rotations and pass them directly to
`verify_compressed_wraps_proof` and `verify_uncompressed_wraps_proof`, without
re-encoding the vector. Both methods decode the ledger ID and use its first element
as the expected genesis address-book hash. They do not check its genesis hints-key
hash; the separate `hints_vk` argument specifies the expected current hints key.
Malformed ledger IDs, including truncated encodings or trailing bytes, return an error.
Proof construction and the Java bridge continue to accept the genesis address-book
hash directly.

## Layout

|                     |                                                                                                                                                             |
|---------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `src/lib.rs`        | the whole library: Schnorr over Grumpkin, the three-round multisignature, address books, the step circuit, and the `WRAPS` entry points                     |
| `examples/demo.rs`  | ten rotations, including serialization round trips and byte sizes for WRAPS inputs and outputs                                                              |
| `examples/stats.rs` | three linked rotations signed by 2-of-3 committees, with serialization checks throughout and final tables of individual type sizes and WRAPS method timings |

The demo uses the library's shared `encode` and `decode` helpers and feeds decoded
values into signing, proof construction, and verification. The verification-key
bytes are round-tripped once. Between rotations, it restores the public parameters
and running state from a serialized checkpoint and derives a fresh compressed
verifier. It reports one representative member's key generation
and signing arguments per book/phase, and the complete round broadcasts as encoded
`RoundMessage` bytes.
Reported return sizes cover successful payloads; raw proof and verifier-key sizes
are printed separately from the surrounding bincode envelopes. Secret keys and seeds
are measured without printing their contents.

## Powers of tau

Compression uses MicroSpartan on both curves, Mercury on BN254, and IPA on Grumpkin.
Mercury uses a KZG universal setup. Put pruned `ppot_pruned_XX.ptau` files under
`params/`, or point `WRAPS_PTAU_DIR` at a directory holding them. The current
MicroSpartan setup needs **power 20** or above; the power-15 file in this crate's
`params/` directory is insufficient.

```bash
WRAPS_PTAU_DIR=/Users/rohit/Research/Nova/params cargo run --release -p novawraps --example demo
```

## Public parameters and keys

`load_public_params` loads powers-of-tau data and builds an owned Nova `PublicParams`
value. Proof construction and uncompressed verification both borrow these parameters.
Each construction call derives its own prover and compressed verifier keys and
checks both returned proofs against the supplied genesis hash and hints key.
Compressed-verifier setup also borrows the public parameters and derives its key
directly through Nova. Once prepared, that key owns everything needed for compressed
verification and does not retain a reference to the public parameters:

```rust
use wraps::{decode, CompressedVerifyingKey, PublicParams, WRAPS};

let pp: PublicParams = WRAPS::load_public_params(&ptau_dir)?;
let serialized_vk: Vec<u8> = WRAPS::get_compressed_verification_key(&pp)?;

// Deserialize the exported key and retain it across compressed proof checks.
let compressed_vk: CompressedVerifyingKey = decode(&serialized_vk)?;
let ledger_id = WRAPS::compute_rotation_message(&genesis_ab, &genesis_hints_vk)?;

let (running, compressed) = WRAPS::construct_wraps_proof(
    &pp, &genesis_hash, &prev_ab, &next_ab,
    previous_running_proof, hints_vk, &multisignature,
)?;
let running_valid = WRAPS::verify_uncompressed_wraps_proof(
    &pp, &running, &ledger_id, hints_vk,
)?;
let compressed_valid = WRAPS::verify_compressed_wraps_proof(
    &compressed_vk, &compressed, &ledger_id, hints_vk,
)?;
```

The serialized verification key is **4,738,776 bytes** for the current circuit and
encoding. It contains the full Nova verifier key, including Poseidon constants and
the secondary IPA basis. "Compressed" refers to the proof this key verifies; the
key itself uses ordinary bincode encoding without additional compression.
This replaces the former 778-byte compact descriptor; regenerate exported
verification-key bytes when updating from that format.

`setup_compressed_verifier(&pp)` uses Nova's setup directly, including the Poseidon
constants and the secondary IPA basis of **131,072 message generators** already
held in the parameters. It derives the compression keys and retains the verifier
key. Keep the returned object and pass it by reference to repeated verification calls.
`CompressedVerifyingKey` implements Serde and supports `encode` and `decode`. To
prepare a verifier in another process, deserialize its exported bytes, or load or
deserialize `PublicParams` there and call `setup_compressed_verifier`.
Uncompressed verification uses `&PublicParams` directly; those parameters support
`encode` and `decode`, with no separate verifier setup or wrapper.

`get_compressed_verification_key(&pp)` calls `setup_compressed_verifier(&pp)` and
serializes the returned `CompressedVerifyingKey` with `encode`. Its transparent
Serde wrapper preserves the underlying Nova verifier-key encoding.

The public API has no separate prover-key setup. `construct_wraps_proof` derives
Nova's prover and compressed verifier keys together on every call, so its runtime
includes that setup cost. Its internal compressed check uses the derived key
directly, without serializing or deserializing the verifier key.

`CompressedWrapsProof` is Nova's compressed SNARK, serialized directly with `encode`
using bincode. Its byte length is deterministic for a fixed circuit shape; there is
no additional zlib compression. Verification keys also use ordinary bincode and
Nova's own Serde implementation. Their encoding depends on the pinned Nova 0.76.0
version and feature layout; review serialization compatibility when upgrading Nova.

The MicroSpartan/Mercury configuration uses different compression and commitment-key
sizes from the previous ordinary-Spartan/HyperKZG configuration. Parameters, keys,
and proofs from that previous configuration are incompatible. Regenerate the
parameters and keys and start a new running proof when switching configurations;
existing powers-of-tau files of sufficient size can be reused. The API simplification
to `load_public_params` does not change the current parameter, key, or proof encoding.

## Signing messages and serialization

Run `stats` for three linked rotations, each signed by 2-of-3 members of
the outgoing committee. The first rotates the genesis book onto itself; the next
two introduce fresh successor books. Each step extends the running proof and verifies
both the running and compressed proofs against the original ledger ID:

```bash
cargo run --release -p novawraps --example stats
```

It requires the same powers-of-tau files as the demo, under `params/` or the directory
specified by `WRAPS_PTAU_DIR`. For example:

```bash
WRAPS_PTAU_DIR=./params cargo run --release -p novawraps --example stats
```

It checks serialization round trips with `encode` and `decode` throughout all three
rotations. Only the last rotation prints a size report: one row per named type or
struct, with separate enum variants where their sizes differ. This includes full
public parameters, signing payloads, and transport messages.
A separate table reports raw proof and serialized verification-key payload sizes
exposed by the API as `Vec<u8>`. The prepared verifier is retained locally for reuse;
its serialized size is represented by the verification-key payload entry.
Both size tables use decimal KB (`1 KB = 1000 bytes`) with three decimal places.

The final timing table lists calls, total milliseconds, and mean milliseconds for
each `WRAPS` method the example invokes. Public-parameter loading, verifier-key
export, and compressed-verifier setup are each timed separately once. Export includes
compressed-verifier setup and serialization.
Proof-construction timing includes internal key derivation and both proof checks.
Per-rotation calls are measured on the third rotation. Timings cover the library call, including
its internal work, and exclude the example's serialization checks, random input
generation, and reporting. Unused methods such as `WRAPS::sentinel_keygen` have no
timing entry.

Each signing round has a distinct serializable payload:

|        Type         |               Field               |
|---------------------|-----------------------------------|
| `MultisigRound1`    | `nonce_commitment: [u8; 32]`      |
| `MultisigRound2<E>` | `nonce_point: E::GE`              |
| `MultisigRound3<E>` | `partial_signature: Signature<E>` |

`SigningProtocolMessage` is an alias for `Vec<u8>`. Each of the three rounds returns
`SigningProtocolObject::ProtocolMessage(bytes)`, already encoded as a tagged
`RoundMessage<E>`. Broadcast these bytes directly, collect received messages in a
`Vec<SigningProtocolMessage>` for each round, and pass those slices to
`WRAPS::signing_protocol`. The library decodes the messages and validates their round
tags. Aggregation returns `SigningProtocolObject::ProtocolOutput(multisignature)`.

The typed payloads and `RoundMessage<E>` remain public and serializable for inspection.
For example, given the result of a round-1 call:

```rust
use wraps::{decode, RoundMessage, SigningProtocolMessage, SigningProtocolObject, E2};

let SigningProtocolObject::ProtocolMessage(bytes) = round1_result else {
    panic!("round 1 must return a broadcast message");
};
println!("Round message: {} bytes", bytes.len());

// Optional inspection; the protocol decodes received messages itself.
let inspected: RoundMessage<E2> = decode(&bytes)?;
assert!(matches!(inspected, RoundMessage::Round1(_)));

let mut round1_messages: Vec<SigningProtocolMessage> = Vec::new();
round1_messages.push(bytes);
// Pass &round1_messages to the next signing_protocol call.
```

Pass the returned bytes without re-encoding them or adding a `RoundMessage` envelope.
`WRAPS::compute_rotation_message` similarly returns `Result<Vec<u8>, WrapsError>`:
the encoded `RotationMessage<E2>` containing the successor address-book hash and hints
verification-key hash. Both the `message_to_sign` argument of `WRAPS::signing_protocol`
and the message argument of `WRAPS::verify_signature` accept `impl AsRef<[u8]>`, so
they can borrow the same returned bytes.

The shared codec exposes `encode<T: Serialize>(&T)` and
`decode<T: DeserializeOwned>(&[u8])`. Both return a `Result` with `WrapsError`, use
bincode's legacy configuration, and `decode` rejects trailing bytes. `RoundMessage`
includes an enum discriminant, so its size differs from the bare round payload.
In `stats`, a `SigningProtocolMessage` row includes its serialized vector length;
the corresponding `RoundMessage` row measures the bytes broadcast by the protocol.
`SigningProtocolPhase`, `SigningProtocolObject<E>`, and the aggregate
`SchnorrMultiSignature<E>` also serialize directly; no application adapters are needed.
The aggregate remains a separate output rather than a fourth `RoundMessage` variant.

The byte-based API replaces typed per-round input slices with
`&[SigningProtocolMessage]` and replaces the `Round1`, `Round2`, `Round3`, and `Output`
variants of `SigningProtocolObject<E>` with `ProtocolMessage` and `ProtocolOutput`.
The named payload structs above describe the decoded messages. `BitVector` is a
fixed-size serializable wrapper: use `let bits: BitVector = [false;
MAX_AB_SIZE].into()` to construct one. It supports indexing and iteration and encodes
exactly `MAX_AB_SIZE` booleans without a vector length prefix. Its encoding therefore
differs from the old demo's `Vec<bool>` adapter. Collect incoming messages in
signing-subset order before passing them to the protocol; network arrival order may
differ.

R2 requires every selected signer's commitment, including the caller's own. R3 checks
all openings and confirms that the supplied secret key and session entropy match the
same selected signer's key and nonce. Aggregation checks every partial signature.
Malformed encodings, wrong round tags, trailing bytes, and incorrect message counts
are rejected. Entropy is required in R1, R2, and R3; it is optional and ignored in
Aggregate. A signing key is required in R3 and is optional and ignored in R1, R2, and
Aggregate. Every phase requires a valid encoded two-field rotation message, including
R1 and R2. A signer must supply the same entropy and message throughout R1, R2, and
R3, because both inputs determine its nonce. Every phase validates the signing book
and rejects bits selecting seats outside that book. R2 onward also requires at least
one selected nonidentity key.
Round messages follow the selected nonidentity keys in address-book order, skipping
sentinel seats even when their bit is set.

The joint signing key must be nonidentity in both native verification and the circuit;
otherwise its aggregate secret would be the publicly known value zero. Individual
sentinel seats remain allowed. This adds a circuit constraint, so public parameters,
prover/verifier keys, and proofs from the previous circuit must be regenerated. The
powers-of-tau files can be reused.

## The halo2curves fork

`halo2curves` 0.9.0 carries a leftover `println!` inside `exp_by_x`
(`src/bn256/curve.rs`) that fires 62 times per call. The BN254 G2 subgroup check reaches
it whenever a G2 point is parsed, so loading the SRS and reading a verifier key each
spray `true`/`false` down stdout. It is gated on halo2curves' `std` feature alone, which
`nova-snark` cannot give up, so features cannot turn it off.

`halo2curves/` is a vendored copy of upstream at the `v0.9.0` tag, wired in through
`[patch.crates-io]` in the workspace root `Cargo.toml`. Nova itself comes from crates.io.
The Halo fork has these changes:

1. `src/bn256/curve.rs` — the two offending lines are gone from `exp_by_x`:

   ```diff
        (0..62).rev().fold(*g2, |mut acc, i| {
   -        #[cfg(feature = "std")]
   -        println!("{}", ((x >> i) & 1) == 1);
   -
            acc = acc.double();
   ```
2. `Cargo.toml` — a `[lints.rust]` block allowing `dead_code` and `unused`. A path
   source does not get `--cap-lints=allow` the way a registry one does, so the crate's
   13 pre-existing warnings would otherwise replay on every build here.
3. `Cargo.toml` — `asm = ["std"]` keeps the feature name that Nova requests on
   x86_64, but no longer forwards it to `halo2derive/asm`. Halo therefore generates
   portable Rust field arithmetic, without its assembly backend's ADX/BMI2 CPU
   requirement. The same backend is selected for Linux and macOS (x86_64 and
   AArch64), and Windows (x86_64).
4. `build.rs` — the obsolete assembly architecture check is removed. It checked
   the build host rather than the compilation target, which would otherwise reject
   an AArch64-hosted build for x86_64 even with the assembly backend disabled.
   The optional `bn256-table` generation remains unchanged.
5. `src/derive/field/tower.rs` — quadratic-field byte and representation decoding
   propagates invalid component encodings as `None`. Upstream unwrapped them
   first, allowing malformed coordinates in serialized G2 points to panic.

The patch applies to the whole graph, so `nova-snark` picks it up too. The workspace
root manifest contains:

```toml
[patch.crates-io]
halo2curves = { path = "src/main/rust/nova-wraps/halo2curves" }
```

Cargo only applies patches from the workspace root. If this crate is moved into
another workspace or built standalone, declare the patch in that build's root
manifest and adjust the path relative to that manifest.

When updating dependencies, verify that `halo2derive/asm` remains absent from the
resolved graph on every supported target. `halo2curves/asm` can remain enabled on
x86_64 because it is now a compatibility feature that only enables `std`. For example:

```bash
cargo tree --target x86_64-unknown-linux-gnu -e features -i halo2derive
```

To rebase onto a newer upstream, reapply the print, field-decoding, and portable-backend fixes,
and reassess whether the lint allowances are still needed. Retire the directory and
its `[patch.crates-io]` entry only when upstream fixes the unwanted print and invalid
field decoding, and the resolved dependencies select portable Halo arithmetic on
all supported targets.

## Hashes

Address-book commitments and rotation signature challenges use Poseidon.
`AddressBookHash<E>` and `HintsVKHash<E>` name the two hashes in each rotation message
and IVC state. `WRAPS::compute_hints_vk_hash` computes SHA-256 of
`b"WRAPS-hints-vk-v1" || hints_vk_bytes`, interprets the entire digest as a big-endian integer, and
reduces it modulo the `E2::Base` field prime to obtain a `HintsVKHash<E2>`.
Rotation signatures and proofs bound to the old Poseidon or unprefixed SHA-256 hints
hashes must be regenerated. This hash change does not change the circuit or Nova setup keys.

Native key proofs of knowledge use SHA-256 under the domain
`WRAPS-schnorr-pok-sha256-mod-v4`, followed by the generator, public key, and commitment.
Each point has a fixed encoding: canonical little-endian field representations of
its affine coordinates and infinity flag. The entire 32-byte digest is interpreted
as a big-endian integer and reduced modulo the scalar-field order `q` to obtain the
`E::Scalar` challenge, without XMD expansion. Direct modular reduction gives a biased
distribution over the scalar field. Rotation signature challenges remain 128 bits.
Multisignature nonce commitments retain their separate SHA-256 domain and all 32
digest bytes. The `sha2` dependency provides SHA-256; `sha3` implements different
algorithms and cannot preserve these hashes.

PoKs produced by earlier hash formats must be regenerated using the same secret keys.
The public `SchnorrPoK::challenge` field has type `E::Scalar`. Public keys and
address-book hashes stay unchanged because the book hash excludes PoKs.
Native PoK construction and validation are internal. `WRAPS::keygen` creates attested
keys; `WRAPS::compute_addressbook_hash` validates a book before hashing it, and
`WRAPS::compute_rotation_message` uses that check to admit the successor book.

`WRAPS::keygen(seed)` expands its 32-byte input into `SHA256(seed || 0x00)` for the
secret key and `SHA256(seed || 0x01)` for the PoK nonce. Each digest seeds a separate
ChaCha20 stream, so the entire attested key is reproducible from the input seed.
The counters are single bytes. This expansion changes the key derived from a given
seed compared with the previous direct-seed sampling.

Signing nonces bind the signing-instance entropy to both fields of the rotation
message. The protocol decodes the message, computes
`SHA256(protocol_instance_entropy || canonical_field_encoding(message[0]) || canonical_field_encoding(message[1]))`,
and uses that digest to seed ChaCha20 before sampling the nonce scalar. Field encodings
are the canonical `PrimeField::to_repr` bytes, in message order, without a bincode
envelope. Reuse the same entropy and message only across the three rounds of one
signing instance. Each signer must choose fresh entropy for every new signing
instance: the same entropy and message produce the same nonce even if the other
signers or their round messages change. This changes signing transcripts, but does
not change the circuit or require new Nova setup parameters.

## Signing: what a signer has to do itself

The step circuit binds the address book to the running state and checks its weight
bounds. Nonidentity key uniqueness and proofs of key possession are checked natively when
`WRAPS::compute_rotation_message` hashes the successor book through
`WRAPS::compute_addressbook_hash`.

So **every signer must build the rotation message in its own process, from the full
`AddressBook` it intends to endorse**:

```rust
let message = WRAPS::compute_rotation_message(&next_ab, hints_vk)?;
```

`WRAPS::signing_protocol` takes the serialized bytes of those two field elements and
cannot look behind them. A signer handed ready-made rotation-message bytes — by the
proposer, or by another signer — has silently skipped the check, and nothing downstream
can notice. What is at stake is the rogue-key defence: a book carrying
`pk_rogue := x·G − Σ pk_j` lets whoever knows `x` produce the whole committee's
signature alone.

Seats keyed to the point at infinity are the exception. Their weight is ignored by the
circuit and native verification alike — out of the total as well as out of the signing
subset — so such a seat is inert whoever built the book. Address-book validation accepts
repeated sentinel keys at any `u64` weight: there is no sum that weight can reach.

## Tests

```bash
WRAPS_PTAU_DIR=./params cargo test --release -p novawraps
```

Everything runs by default. The end-to-end simulations perform a full trusted setup and
several folding and compression steps, so the suite takes a minute or so in release
mode; it needs `ppot_pruned_XX.ptau` files under `params/` or `WRAPS_PTAU_DIR`.
Size reporting lives in the examples: `stats` prints individual type and
artifact sizes on the third rotation, while `demo` reports serialization sizes
throughout its ten rotations.
