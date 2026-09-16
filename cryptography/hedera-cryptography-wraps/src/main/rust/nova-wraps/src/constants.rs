//! Shared protocol sizes, bounds, and hash domain separators.

pub(crate) use nova_snark::constants::NUM_CHALLENGE_BITS;

/// The largest address book the circuit can take.
///
/// A committee may be any size up to this. The circuit's shape is fixed, so a shorter
/// book is padded internally to exactly this many entries before it is
/// hashed or proven — which means a book's commitment is always the commitment to its
/// *padded* form, and the two must never be computed from anything else.
pub const MAX_AB_SIZE: usize = 64;

/// Size in bytes of the entropy used for key generation and signing sessions.
///
/// Signing uses one seed per signer per protocol instance: reuse it across that
/// instance's rounds and supply a fresh seed for the next instance.
/// See [`crate::wraps::WRAPS::signing_protocol`].
pub const ENTROPY_SIZE: usize = 32;

/// Number of hints verification-key bytes packed into each little-endian field input.
pub(crate) const HINTS_VK_CHUNK_SIZE: usize = 8;

/// Bit width of each seat's weight and the committee's total effective weight.
pub(crate) const WEIGHT_BITS: usize = u64::BITS as usize;

/// Poseidon domain separator for `H(ab)`, the address-book commitment.
pub(crate) const DS_ADDRESS_BOOK: u32 = 1;

/// Poseidon domain separator for the hash of a serialized hints verification key.
pub(crate) const DS_HINTS_VK: u32 = 2;

/// Poseidon domain separator for the Schnorr challenge `H(pk, r, m)`.
pub(crate) const DS_CHALLENGE: u32 = 3;

/// Domain separator for a native SHA-256 proof-of-knowledge challenge with scalar reduction.
pub(crate) const DST_POK: &[u8] = b"WRAPS-schnorr-pok-sha256-mod-v4";

/// Domain separator for a round-1 commitment to a multisignature nonce.
///
/// A byte string rather than a small integer, because unlike the Poseidon separators
/// this one prefixes a byte-oriented hash.
pub(crate) const DST_NONCE_COMMITMENT: &[u8] = b"WRAPS-schnorr-nonce-commitment-v1";
