// SPDX-License-Identifier: Apache-2.0

use ark_ff::{field_hashers::{DefaultFieldHasher, HashToField}, PrimeField};
use ark_serialize::CanonicalSerialize;
use sha2::Sha256;

use crate::errors::HinTSError;

/// A Fiat-Shamir transcript that only grows. Every challenge hashes everything absorbed so
/// far under a domain separator of its own, so a challenge binds every item absorbed before
/// it. Items go in as their compressed canonical encoding; callers only absorb fixed-width
/// items, so the concatenation is unambiguous.
pub(crate) struct Transcript {
    bytes: Vec<u8>,
}

impl Transcript {
    pub(crate) fn new() -> Self {
        Transcript { bytes: Vec::new() }
    }

    /// appends the compressed canonical encoding of `item`
    pub(crate) fn absorb<T: CanonicalSerialize>(&mut self, item: &T) -> Result<(), HinTSError> {
        item.serialize_compressed(&mut self.bytes)?;
        Ok(())
    }

    /// hashes everything absorbed so far to a field element, under `dst`
    pub(crate) fn challenge<F: PrimeField>(&self, dst: &[u8]) -> F {
        let hasher = <DefaultFieldHasher<Sha256> as HashToField<F>>::new(dst);
        hasher.hash_to_field(&self.bytes, 1)[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr as F;

    const DST_A: &[u8] = b"TRANSCRIPT_TEST_A";
    const DST_B: &[u8] = b"TRANSCRIPT_TEST_B";

    #[test]
    fn test_challenges_bind_content_order_and_domain() {
        let mut t = Transcript::new();
        t.absorb(&F::from(1u64)).unwrap();
        let first: F = t.challenge(DST_A);

        // deterministic, and separated by domain
        assert_eq!(first, t.challenge::<F>(DST_A));
        assert_ne!(first, t.challenge::<F>(DST_B));

        // absorbing more moves the challenge, and drawing one does not consume anything
        t.absorb(&F::from(2u64)).unwrap();
        let second: F = t.challenge(DST_A);
        assert_ne!(first, second);
        assert_eq!(second, t.challenge::<F>(DST_A));

        // the same items in another order give another challenge
        let mut u = Transcript::new();
        u.absorb(&F::from(2u64)).unwrap();
        u.absorb(&F::from(1u64)).unwrap();
        assert_ne!(second, u.challenge::<F>(DST_A));
    }
}
