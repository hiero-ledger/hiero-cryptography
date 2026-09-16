//! WRAPS: address-book rotation attested by a weighted Schnorr multisignature, folded with Nova.
//!
//! A committee is an *address book*: up to [`MAX_AB_SIZE`] entries of
//! `(node id, (public key, proof of knowledge), weight)`. A book may be any size up to
//! that; since the circuit's shape is fixed, a shorter one is padded out with zero-weight
//! dummy seats before it is hashed or proven, so a committee's commitment never depends
//! on how many seats it happens to fill. Rotating the committee means
//! producing a new address book that the outgoing one has jointly signed, and the IVC
//! carries a proof that every rotation since genesis was authorised this way.
//! Nonidentity public keys must be unique within a book. Sentinel keys may repeat;
//! they are omitted from the signing rounds even when selected by the bitvector.
//!
//! Use [`WRAPS`] with the public address-book, signing, and key types.
//! Serialized proofs and verifier keys use `Vec<u8>`.
//! Padding, signing-subset selection, and the underlying cryptographic helpers are
//! internal implementation details.
//!
//! The running state has arity 2: `z_i = [H(ab_i), H(hints_vk_i)]`. As non-deterministic
//! advice a step takes the outgoing address book, a bitvector naming which members
//! signed, the aggregate signature, and the two hashes that make up the next state. The
//! step circuit checks that
//!
//!   1. the advised address book is the one the state commits to: `H(ab_i) == z_i[0]`,
//!   2. the members named by the bitvector carry **strictly more than half** of the
//!      book's total weight,
//!   3. the joint key `PK = Σ_{j ∈ bitvector} pk_j` — aggregated *inside* the circuit,
//!      over the signing subset only — verifies the aggregate signature on the rotation
//!      message `[H(ab_{i+1}), H(hints_vk_{i+1})]`,
//!
//! and outputs `z_{i+1} = [H(ab_{i+1}), H(hints_vk_{i+1})]`.
//!
//! Since step `i+1` re-derives `H(ab_{i+1})` from its own advice and compares it against
//! its input, the message signed at step `i` is forced to be the commitment to the book
//! in force at step `i+1`. So each committee attests its successor, and a proof against
//! `(n, z_0, z_n)` establishes a chain of `n` authorised rotations from the genesis book
//! committed by `z_0` — without the verifier seeing any intermediate book or signature.
//!
//! # Curve choice
//!
//! Signatures live on the *secondary* curve `E2` (Grumpkin), whose base field is the
//! scalar field of the primary SNARK `E1` (BN254). The step circuit is an R1CS over
//! `E1::Scalar == E2::Base`, so Grumpkin coordinates are native to the circuit and the
//! group operations use Nova's `AllocatedPoint` gadget with no non-native emulation.
//!
//! # Weight threshold
//!
//! [`WRAPS::verify_signature`] and the circuit agree on the same rule: the signing subset is
//! accepted only when `signing_weight > total_weight / 2`, using integer division.
//! Ties fail. [`Weight`] is a `u64`, and the total effective weight must also fit in a
//! `u64`. Native summation rejects overflow; the circuit constrains every seat's weight
//! and the total to 64 bits. A seat keyed to the point at infinity carries no weight
//! in either sum.
//!
//! # Trust boundary
//!
//! The step circuit does not validate the keys in the address book it is handed. It
//! cannot: checking a proof of possession per seat would mean 64 more Schnorr
//! verifications inside the circuit. What it does instead is bind the book to the
//! running state through `H(ab)`, so the book it sees is the one the *previous*
//! committee signed. Key validity is therefore established once, natively, through
//! [`WRAPS::compute_rotation_message`], when a committee endorses its successor.
//! That native check also enforces uniqueness of nonidentity keys; the circuit does
//! not enforce key uniqueness.
//!
//! Two things follow, and they are the whole trust boundary of this crate.
//!
//! **Every signer must build the rotation message itself, from the full address book it
//! intends to endorse, using [`WRAPS::compute_rotation_message`].** That function
//! validates the next book before producing its rotation message.
//! [`WRAPS::signing_protocol`] decodes the message into two field elements and cannot
//! look behind them; a signer handed a serialized [`RotationMessage`] over the wire
//! has no way to check what it is endorsing, or to tell that nobody else did either.
//!
//! **What that check buys** is a unique public key and proof of possession for every
//! non-identity seat. Without the possession check, a book can carry a rogue key
//! `pk_rogue := x·G − Σ pk_j` whose author can produce the joint key's signature alone.
//! Weight bounds are checked both natively and in the circuit.
//!
//! What is *not* on this list is the point at infinity. An identity seat's weight is
//! ignored by the circuit and native verification alike, in the total as well as in
//! the signing subset, so such a seat is inert no matter who built the book — which is
//! why address-book validation accepts one at any `u64` weight.
mod circuit;
mod constants;
mod error;
mod poseidon;
mod schnorr;
mod utils;
mod verification_key;
mod wraps;

#[doc(hidden)]
pub use circuit::RotationCircuit;
pub use constants::{ENTROPY_SIZE, MAX_AB_SIZE};
pub use error::WrapsError;
pub use schnorr::{
  MultisigRound1, MultisigRound2, MultisigRound3, RoundMessage, SchnorrAttestedPubKey,
  SchnorrChallenge, SchnorrPoK, SchnorrPoKChallenge, SchnorrPublicKey, SchnorrResponse,
  SchnorrSecretKey, Signature,
};
pub use utils::{decode, encode, BitVector};
pub use wraps::{
  AddressBook, AddressBookEntry, AddressBookHash, Base, CompressedVerifyingKey, HintsVKHash,
  NodeId, PublicParams, RotationMessage, SchnorrMultiSignature, SigningProtocolMessage,
  SigningProtocolObject, SigningProtocolPhase, Weight, E1, E2, WRAPS,
};

#[cfg(test)]
mod tests;
