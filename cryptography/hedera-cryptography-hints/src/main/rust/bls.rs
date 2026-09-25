// SPDX-License-Identifier: Apache-2.0

//! Standalone BLS multi-signature verification over the BLS12-381 curve.
//!
//! This module is deliberately independent of the hinTS scheme in [`crate::hints`], but
//! it follows the same conventions, so material produced there can be verified here:
//! public keys are points in G1, signatures are points in G2, a signature on `msg` under
//! the secret key `sk` is `sk · H(msg)`, and it verifies iff `e(pk, H(msg)) == e([1]_1, sig)`.
//!
//! Aggregation is the plain sum of the selected public keys. Plain summation is only
//! sound against rogue-key attacks when every public key in the vector has been
//! accompanied by a proof of possession of its secret key, which is why messages are
//! hashed into G2 under the `POP` domain separation tag of the IETF BLS specification.
//! Verifying those proofs is the caller's responsibility; this module does not do it.
//!
//! All inputs and outputs are byte arrays using arkworks' canonical serialization.
//! Note that this is *not* the ZCash/IETF wire format used by, e.g., `blst`: arkworks
//! writes coordinates little-endian with the flags in the most significant bits of the
//! last byte. Mixing the two encodings is safe in the sense that a point in the wrong
//! encoding is overwhelmingly likely to be rejected, rather than silently misread.

use ark_bls12_381::{g1::Config as G1Config, g2::Config as G2Config, Bls12_381};
use ark_ec::hashing::{
    curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve,
};
use ark_ec::pairing::Pairing;
use ark_ec::short_weierstrass::{Affine, Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::Sha256;

use crate::errors::HinTSError;

/// Pairing friendly curve powering the BLS signature scheme
pub type Curve = Bls12_381;
/// Type denoting a public key, which is a G1 group element
pub type PublicKey = Affine<G1Config>;
/// Type denoting a signature, which is a G2 group element
pub type Signature = Affine<G2Config>;
/// Represents a point in G1 (projective coordinates)
type G1ProjectivePoint = Projective<G1Config>;
/// Represents a point in G2 (projective coordinates)
type G2ProjectivePoint = Projective<G2Config>;

/// Domain separation tag for hashing a message into G2; the `POP` suffix denotes the
/// proof-of-possession variant of the IETF BLS signature specification, and matches the
/// tag used by [`crate::hints`], so that the two modules sign and verify identically.
const DST_G2: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Size of a public key in arkworks' compressed serialization
pub const COMPRESSED_PUBLIC_KEY_SIZE: usize = 48;
/// Size of a public key in arkworks' uncompressed serialization
pub const UNCOMPRESSED_PUBLIC_KEY_SIZE: usize = 96;
/// Size of a signature in arkworks' compressed serialization
pub const COMPRESSED_SIGNATURE_SIZE: usize = 96;
/// Size of a signature in arkworks' uncompressed serialization
pub const UNCOMPRESSED_SIGNATURE_SIZE: usize = 192;

pub struct Bls;

impl Bls {
    /// Verifies a BLS signature on `msg` under the given public key.
    ///
    /// The public key must be a serialized G1 point and the signature a serialized G2
    /// point, either of which may be given in compressed or uncompressed form; both are
    /// checked to be on the curve and in the prime order subgroup while being parsed.
    ///
    /// # Arguments
    /// * `msg` - the signed message
    /// * `public_key` - the serialized public key of the signer
    /// * `signature` - the serialized signature to check
    ///
    /// # Returns
    /// `Ok(true)` if the signature verifies, `Ok(false)` if it does not, and an error if
    /// an input is not a well-formed group element. Note that an identity public key or
    /// an identity signature yields `Ok(false)`: those satisfy the pairing equation
    /// trivially, and are therefore treated as a failed verification rather than a valid
    /// signature by an unknown signer.
    pub fn verify(msg: &[u8], public_key: &[u8], signature: &[u8]) -> Result<bool, HinTSError> {
        let pk = deserialize_public_key(public_key)?;
        let sig = deserialize_signature(signature)?;

        // Zero values satisfy the pairing equation trivially, for any message.
        if pk.is_zero() || sig.is_zero() {
            return Ok(false);
        }

        // e(pk, H(msg)) == e([1]_1, sig)
        let lhs = <Curve as Pairing>::pairing(pk, hash_to_g2(msg)?);
        let rhs = <Curve as Pairing>::pairing(PublicKey::generator(), sig);
        Ok(lhs == rhs)
    }

    /// Aggregates the public keys selected by the bitvector into a single public key,
    /// which is the sum of the selected G1 points. The aggregate verifies the sum of the
    /// corresponding signatures on a common message, via [`Bls::verify`].
    ///
    /// Only the selected entries are parsed, so an entry the bitvector skips may hold
    /// arbitrary bytes, e.g. a placeholder for a party that never published a key.
    ///
    /// # Arguments
    /// * `public_keys` - the serialized public keys, one per party
    /// * `bitvector` - flags marking which of those public keys take part, of equal length
    ///
    /// # Returns
    /// The aggregate public key in arkworks' uncompressed serialization, or an error if
    /// the two inputs disagree in length, if the bitvector selects no key at all, if a
    /// selected key is malformed or is the identity element, or if the selected keys sum
    /// to the identity element (such an aggregate would verify nothing).
    pub fn aggregate_public_keys(
        public_keys: &[impl AsRef<[u8]>],
        bitvector: &[bool],
    ) -> Result<Vec<u8>, HinTSError> {
        if public_keys.len() != bitvector.len() {
            return Err(HinTSError::InvalidInput(format!(
                "public_keys and bitvector must be of the same size. Got {} and {}",
                public_keys.len(),
                bitvector.len()
            )));
        }

        let mut aggregate = G1ProjectivePoint::zero();
        let mut num_selected = 0usize;
        for (i, (public_key, selected)) in public_keys.iter().zip(bitvector.iter()).enumerate() {
            if !selected {
                continue;
            }

            let pk = deserialize_public_key(public_key.as_ref())?;
            // An identity public key contributes nothing and signals a malformed input.
            if pk.is_zero() {
                return Err(HinTSError::InvalidInput(format!(
                    "public key at index {i} is the identity element"
                )));
            }

            aggregate += pk;
            num_selected += 1;
        }

        if num_selected == 0 {
            return Err(HinTSError::InvalidInput(
                "bitvector selects no public key".to_string(),
            ));
        }

        let aggregate = aggregate.into_affine();
        if aggregate.is_zero() {
            return Err(HinTSError::InvalidInput(
                "the selected public keys sum to the identity element".to_string(),
            ));
        }

        serialize_public_key(&aggregate)
    }
}

/// deserializes a public key from its compressed or uncompressed form, validating that
/// it is on the curve and in the prime order subgroup
fn deserialize_public_key(bytes: &[u8]) -> Result<PublicKey, HinTSError> {
    match bytes.len() {
        COMPRESSED_PUBLIC_KEY_SIZE => Ok(PublicKey::deserialize_compressed(bytes)?),
        UNCOMPRESSED_PUBLIC_KEY_SIZE => Ok(PublicKey::deserialize_uncompressed(bytes)?),
        len => Err(HinTSError::InvalidInput(format!(
            "public key must be {COMPRESSED_PUBLIC_KEY_SIZE} bytes (compressed) \
             or {UNCOMPRESSED_PUBLIC_KEY_SIZE} bytes (uncompressed). Got {len}"
        ))),
    }
}

/// deserializes a signature from its compressed or uncompressed form, validating that
/// it is on the curve and in the prime order subgroup
fn deserialize_signature(bytes: &[u8]) -> Result<Signature, HinTSError> {
    match bytes.len() {
        COMPRESSED_SIGNATURE_SIZE => Ok(Signature::deserialize_compressed(bytes)?),
        UNCOMPRESSED_SIGNATURE_SIZE => Ok(Signature::deserialize_uncompressed(bytes)?),
        len => Err(HinTSError::InvalidInput(format!(
            "signature must be {COMPRESSED_SIGNATURE_SIZE} bytes (compressed) \
             or {UNCOMPRESSED_SIGNATURE_SIZE} bytes (uncompressed). Got {len}"
        ))),
    }
}

/// serializes a public key into its uncompressed form
fn serialize_public_key(public_key: &PublicKey) -> Result<Vec<u8>, HinTSError> {
    let mut buf = Vec::with_capacity(UNCOMPRESSED_PUBLIC_KEY_SIZE);
    public_key.serialize_uncompressed(&mut buf)?;
    Ok(buf)
}

/// hashes a byte array to a G2 group element
fn hash_to_g2(msg: &[u8]) -> Result<Signature, HinTSError> {
    let g2_mapper = MapToCurveBasedHasher::<
        G2ProjectivePoint,
        DefaultFieldHasher<Sha256, 128>,
        WBMap<G2Config>,
    >::new(DST_G2)?;
    g2_mapper.hash(msg).map_err(HinTSError::HashingError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fq, Fr};
    use ark_ff::One;
    use ark_std::UniformRand;
    use rand_chacha::rand_core::SeedableRng;

    const MSG: &[u8] = b"hello multisig";

    /// samples a deterministic key pair from the given seed byte
    fn keypair(seed: u8) -> (Fr, PublicKey) {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([seed; 32]);
        let sk = Fr::rand(&mut rng);
        (sk, (PublicKey::generator() * sk).into_affine())
    }

    /// signs a message the same way [`crate::hints::HinTS::sign`] does
    fn sign(msg: &[u8], sk: &Fr) -> Signature {
        (hash_to_g2(msg).unwrap() * sk).into_affine()
    }

    fn serialize_uncompressed<T: CanonicalSerialize>(t: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        t.serialize_uncompressed(&mut buf).unwrap();
        buf
    }

    fn serialize_compressed<T: CanonicalSerialize>(t: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        t.serialize_compressed(&mut buf).unwrap();
        buf
    }

    /// finds a point that is on the curve but outside the prime order subgroup of G1
    fn non_subgroup_public_key() -> PublicKey {
        let mut x = Fq::one();
        loop {
            if let Some(point) = PublicKey::get_point_from_x_unchecked(x, false) {
                if !point.is_in_correct_subgroup_assuming_on_curve() {
                    return point;
                }
            }
            x += Fq::one();
        }
    }

    #[test]
    fn test_verify_accepts_both_encodings() {
        let (sk, pk) = keypair(1);
        let sig = sign(MSG, &sk);

        for pk_bytes in [serialize_uncompressed(&pk), serialize_compressed(&pk)] {
            for sig_bytes in [serialize_uncompressed(&sig), serialize_compressed(&sig)] {
                assert!(Bls::verify(MSG, &pk_bytes, &sig_bytes).unwrap());
            }
        }
    }

    #[test]
    fn test_verify_rejects_invalid_signatures() {
        let (sk, pk) = keypair(1);
        let (other_sk, other_pk) = keypair(2);
        let sig = serialize_uncompressed(&sign(MSG, &sk));
        let pk_bytes = serialize_uncompressed(&pk);

        // a different message
        assert!(!Bls::verify(b"goodbye multisig", &pk_bytes, &sig).unwrap());
        // a different signer's key
        assert!(!Bls::verify(MSG, &serialize_uncompressed(&other_pk), &sig).unwrap());
        // a different signer's signature
        assert!(!Bls::verify(MSG, &pk_bytes, &serialize_uncompressed(&sign(MSG, &other_sk))).unwrap());
        // an empty message is a perfectly good message, but not the signed one
        assert!(!Bls::verify(b"", &pk_bytes, &sig).unwrap());
    }

    #[test]
    fn test_verify_rejects_identity_inputs() {
        let (sk, pk) = keypair(1);
        let identity_pk = serialize_uncompressed(&PublicKey::zero());
        let identity_sig = serialize_uncompressed(&Signature::zero());

        // an identity public key and signature satisfy the pairing equation trivially
        assert!(!Bls::verify(MSG, &identity_pk, &identity_sig).unwrap());
        assert!(!Bls::verify(MSG, &identity_pk, &serialize_uncompressed(&sign(MSG, &sk))).unwrap());
        assert!(!Bls::verify(MSG, &serialize_uncompressed(&pk), &identity_sig).unwrap());
    }

    #[test]
    fn test_verify_rejects_malformed_inputs() {
        let (sk, pk) = keypair(1);
        let pk_bytes = serialize_uncompressed(&pk);
        let sig_bytes = serialize_uncompressed(&sign(MSG, &sk));

        // wrong lengths
        assert!(Bls::verify(MSG, &[], &sig_bytes).is_err());
        assert!(Bls::verify(MSG, &pk_bytes[..95], &sig_bytes).is_err());
        assert!(Bls::verify(MSG, &sig_bytes, &sig_bytes).is_err());
        assert!(Bls::verify(MSG, &pk_bytes, &[]).is_err());
        assert!(Bls::verify(MSG, &pk_bytes, &pk_bytes).is_err());

        // right length, garbage content
        assert!(Bls::verify(MSG, &vec![7u8; UNCOMPRESSED_PUBLIC_KEY_SIZE], &sig_bytes).is_err());
        assert!(Bls::verify(MSG, &pk_bytes, &vec![7u8; UNCOMPRESSED_SIGNATURE_SIZE]).is_err());

        // a point on the curve, but outside the prime order subgroup
        let rogue = serialize_uncompressed(&non_subgroup_public_key());
        assert_eq!(UNCOMPRESSED_PUBLIC_KEY_SIZE, rogue.len());
        assert!(Bls::verify(MSG, &rogue, &sig_bytes).is_err());
    }

    #[test]
    fn test_aggregate_public_keys_verifies_aggregate_signature() {
        let keys: Vec<(Fr, PublicKey)> = (0..5).map(keypair).collect();
        let public_keys: Vec<Vec<u8>> = keys.iter().map(|(_, pk)| serialize_uncompressed(pk)).collect();
        let bitvector = [true, false, true, true, false];

        let aggregate_pk = Bls::aggregate_public_keys(&public_keys, &bitvector).unwrap();
        assert_eq!(UNCOMPRESSED_PUBLIC_KEY_SIZE, aggregate_pk.len());

        // the aggregate public key is the sum of the selected public keys
        let expected = keys
            .iter()
            .zip(bitvector.iter())
            .filter(|(_, &selected)| selected)
            .fold(G1ProjectivePoint::zero(), |acc, ((_, pk), _)| acc + pk)
            .into_affine();
        assert_eq!(serialize_uncompressed(&expected), aggregate_pk);

        // and it verifies the sum of the selected signatures on the message
        let aggregate_sig = keys
            .iter()
            .zip(bitvector.iter())
            .filter(|(_, &selected)| selected)
            .fold(G2ProjectivePoint::zero(), |acc, ((sk, _), _)| acc + sign(MSG, sk))
            .into_affine();
        assert!(Bls::verify(MSG, &aggregate_pk, &serialize_uncompressed(&aggregate_sig)).unwrap());

        // a signature missing one of the aggregated signers does not verify
        let short_sig = keys
            .iter()
            .zip(bitvector.iter())
            .filter(|(_, &selected)| selected)
            .skip(1)
            .fold(G2ProjectivePoint::zero(), |acc, ((sk, _), _)| acc + sign(MSG, sk))
            .into_affine();
        assert!(!Bls::verify(MSG, &aggregate_pk, &serialize_uncompressed(&short_sig)).unwrap());
    }

    #[test]
    fn test_aggregate_public_keys_accepts_both_encodings() {
        let keys: Vec<(Fr, PublicKey)> = (0..3).map(keypair).collect();
        let bitvector = [true, true, false];

        let uncompressed: Vec<Vec<u8>> = keys.iter().map(|(_, pk)| serialize_uncompressed(pk)).collect();
        let compressed: Vec<Vec<u8>> = keys.iter().map(|(_, pk)| serialize_compressed(pk)).collect();

        assert_eq!(
            Bls::aggregate_public_keys(&uncompressed, &bitvector).unwrap(),
            Bls::aggregate_public_keys(&compressed, &bitvector).unwrap()
        );
    }

    #[test]
    fn test_aggregate_public_keys_of_a_single_key_is_that_key() {
        let (sk, pk) = keypair(1);
        let public_keys = vec![serialize_uncompressed(&pk)];

        let aggregate_pk = Bls::aggregate_public_keys(&public_keys, &[true]).unwrap();
        assert_eq!(public_keys[0], aggregate_pk);
        assert!(Bls::verify(MSG, &aggregate_pk, &serialize_uncompressed(&sign(MSG, &sk))).unwrap());
    }

    #[test]
    fn test_aggregate_public_keys_ignores_unselected_entries() {
        let (_, pk) = keypair(1);
        // the unselected entries hold bytes that would never parse as a public key
        let public_keys = vec![vec![], serialize_uncompressed(&pk), vec![9u8; 17]];

        let aggregate_pk = Bls::aggregate_public_keys(&public_keys, &[false, true, false]).unwrap();
        assert_eq!(public_keys[1], aggregate_pk);
    }

    #[test]
    fn test_aggregate_public_keys_rejects_invalid_inputs() {
        let keys: Vec<(Fr, PublicKey)> = (0..3).map(keypair).collect();
        let public_keys: Vec<Vec<u8>> = keys.iter().map(|(_, pk)| serialize_uncompressed(pk)).collect();

        // the bitvector must have one flag per public key
        assert!(Bls::aggregate_public_keys(&public_keys, &[true, true]).is_err());
        assert!(Bls::aggregate_public_keys(&public_keys, &[true; 4]).is_err());
        // and must select at least one of them
        assert!(Bls::aggregate_public_keys(&public_keys, &[false; 3]).is_err());
        // an empty universe selects nothing either
        assert!(Bls::aggregate_public_keys(&Vec::<Vec<u8>>::new(), &[]).is_err());

        // a selected key that is malformed, or outside the prime order subgroup
        let mut malformed = public_keys.clone();
        malformed[1] = vec![7u8; UNCOMPRESSED_PUBLIC_KEY_SIZE];
        assert!(Bls::aggregate_public_keys(&malformed, &[true; 3]).is_err());
        malformed[1] = serialize_uncompressed(&non_subgroup_public_key());
        assert!(Bls::aggregate_public_keys(&malformed, &[true; 3]).is_err());

        // a selected key that is the identity element
        let mut identity = public_keys.clone();
        identity[1] = serialize_uncompressed(&PublicKey::zero());
        assert!(Bls::aggregate_public_keys(&identity, &[true; 3]).is_err());
    }

    #[test]
    fn test_aggregate_public_keys_rejects_cancelling_keys() {
        let (sk, pk) = keypair(1);
        let negated = (PublicKey::generator() * -sk).into_affine();
        let public_keys = vec![serialize_uncompressed(&pk), serialize_uncompressed(&negated)];

        assert!(Bls::aggregate_public_keys(&public_keys, &[true, true]).is_err());
    }

    #[test]
    fn test_interoperability_with_the_hints_module() {
        // a signature produced by the hinTS signer verifies under this module, which
        // pins down that both use the same domain separation tag and group assignment
        let sk = crate::hints::HinTS::keygen([42u8; 32]).unwrap();
        let pk = (PublicKey::generator() * *sk).into_affine();
        let sig = crate::hints::HinTS::sign(MSG, &sk).unwrap();

        assert!(Bls::verify(MSG, &serialize_uncompressed(&pk), &serialize_uncompressed(&sig)).unwrap());
        assert!(!Bls::verify(b"another message", &serialize_uncompressed(&pk), &serialize_uncompressed(&sig)).unwrap());
    }
}
