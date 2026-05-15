// SPDX-License-Identifier: Apache-2.0
// Portions of this file are derived from arkworks-rs/r1cs-tutorial under Apache 2.0 License.

use ark_crypto_primitives::Error;
use ark_ec::{CurveGroup, AffineRepr};
use ark_ff::{fields::PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{Zero, rand::{Rng, SeedableRng}, hash::Hash, marker::PhantomData, vec::Vec, ops::*};
use blake2::Blake2s;
use digest::Digest;

use crate::utils::serialize;
use super::SignatureScheme;

pub mod constraints;

pub struct Schnorr<C: CurveGroup> {
    _group: PhantomData<C>,
}

#[derive(Clone, Default, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct Parameters<C: CurveGroup> {
    pub generator: C::Affine,
    pub salt: Option<[u8; 32]>,
}

pub type PublicKey<C> = <C as CurveGroup>::Affine;

pub type SecretKey<C> = <<C as CurveGroup>::Affine as AffineRepr>::ScalarField;

#[derive(Clone, Default, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct Signature<C: CurveGroup> {
    pub prover_response: C::ScalarField,
    pub verifier_challenge: C::ScalarField,
}

impl<C: CurveGroup + Hash> SignatureScheme for Schnorr<C>
where
    C::ScalarField: PrimeField,
{
    type Parameters = Parameters<C>;
    type PublicKey = PublicKey<C>;
    type SecretKey = SecretKey<C>;
    type Signature = Signature<C>;

    fn setup(_entropy: [u8; 32]) -> Result<Self::Parameters, Error> {
        let salt = None;
        let generator = C::generator().into();

        Ok(Parameters { generator, salt })
    }

    fn keygen(
        parameters: &Self::Parameters,
        entropy: [u8; 32],
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error> {
        let mut csprng = ark_std::rand::rngs::StdRng::from_seed(entropy);
        // secret is a random scalar x, and the pubkey is y = xG
        let secret_key = C::ScalarField::rand(&mut csprng);
        let public_key = parameters.generator.mul(secret_key).into();

        Ok(( public_key, secret_key ))
    }

    fn sign(
        parameters: &Self::Parameters,
        sk: &Self::SecretKey,
        message: &[u8],
        entropy: [u8; 32],
    ) -> Result<Self::Signature, Error> {
        let mut csprng = ark_std::rand::rngs::StdRng::from_seed(entropy);
        // (k, e);
        let (random_scalar, verifier_challenge) = {
            let public_key = parameters.generator.mul(sk).into();
            // Sample a random scalar `k` from the prime scalar field.
            let random_scalar: C::ScalarField = C::ScalarField::rand(&mut csprng);
            // Commit to the random scalar via r := k · G.
            // This is the prover's first msg in the Sigma protocol.
            let prover_commitment = parameters.generator.mul(random_scalar).into_affine();

            // Hash everything to get verifier challenge.
            // e := H(salt || pubkey || r || msg);
            let mut hash_input = Vec::new();
            if parameters.salt != None {
                hash_input.extend_from_slice(&parameters.salt.unwrap());
            }
            hash_input.extend_from_slice(&serialize(&public_key));
            hash_input.extend_from_slice(&serialize(&prover_commitment));
            hash_input.extend_from_slice(message);

            let verifier_challenge_digest: [u8; 32] = Blake2s::digest(&hash_input).into();
            let verifier_challenge = C::ScalarField::from_le_bytes_mod_order(&verifier_challenge_digest[0..31]);

            (random_scalar, verifier_challenge)
        };

        // k - xe;
        let prover_response = random_scalar - (verifier_challenge * sk);
        let signature = Signature { prover_response, verifier_challenge };

        Ok(signature)
    }

    fn verify(
        parameters: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool, Error> {
        let Signature {
            prover_response,
            verifier_challenge,
        } = signature;
        // sG = kG - eY
        // kG = sG + eY
        // so we first solve for kG.
        let mut claimed_prover_commitment = parameters.generator.mul(*prover_response);
        let public_key_times_verifier_challenge = pk.mul(verifier_challenge);
        claimed_prover_commitment += &public_key_times_verifier_challenge;
        let claimed_prover_commitment = claimed_prover_commitment.into_affine();

        // e = H(salt, kG, msg)
        let mut hash_input = Vec::new();
        if parameters.salt != None {
            hash_input.extend_from_slice(&parameters.salt.unwrap());
        }
        hash_input.extend_from_slice(&serialize(pk));
        hash_input.extend_from_slice(&serialize(&claimed_prover_commitment));
        hash_input.extend_from_slice(message);

        // cast the hash output to get e
        let obtained_verifier_challenge_digest: [u8; 32] = Blake2s::digest(&hash_input).into();
        let obtained_verifier_challenge = C::ScalarField::from_le_bytes_mod_order(&obtained_verifier_challenge_digest[0..31]);
        Ok(*verifier_challenge == obtained_verifier_challenge)
    }
}

pub struct ThresholdSchnorr<C: CurveGroup> {
    _group: PhantomData<C>,
}

pub type ThresholdSchnorrMessage1 = [u8; 32];
pub type ThresholdSchnorrMessage2<C> = <C as CurveGroup>::Affine;
pub type ThresholdSchnorrMessage3<C> = Signature<C>;

impl<C: CurveGroup + Hash> ThresholdSchnorr<C> where C::ScalarField: PrimeField,
{
    fn get_pseudorandom_scalar(entropy: [u8; 32]) -> C::ScalarField {
        let mut csprng = ark_std::rand::rngs::StdRng::from_seed(entropy);
        C::ScalarField::rand(&mut csprng)
    }

    fn compute_challenge(
        parameters: &Parameters<C>,
        round1_messages: &[ThresholdSchnorrMessage1],
        round2_messages: &[ThresholdSchnorrMessage2<C>],
        aggregate_pk: &PublicKey<C>,
        message_to_sign: &[u8],
    ) -> Result<C::ScalarField, ThresholdSchnorrError> {
        let mut aggregate_prover_commitment = C::Affine::zero();
        for (i, msg) in round2_messages.into_iter().enumerate() {
            let hash_commitment: [u8; 32] = Blake2s::digest(&serialize(msg)).into();
            if round1_messages[i] != hash_commitment {
                return Err(ThresholdSchnorrError::InvalidInput);
            }

            aggregate_prover_commitment = aggregate_prover_commitment.add(msg).into_affine();
        }

        // Hash everything to get verifier challenge.
        // e := H(salt || pubkey || r || msg);
        let mut hash_input = Vec::new();
        if parameters.salt != None {
            hash_input.extend_from_slice(&parameters.salt.unwrap());
        }
        hash_input.extend_from_slice(&serialize(&aggregate_pk));
        hash_input.extend_from_slice(&serialize(&aggregate_prover_commitment));
        hash_input.extend_from_slice(message_to_sign);
        let verifier_challenge: [u8; 32] = Blake2s::digest(&hash_input).into();
        let verifier_challenge_fe = C::ScalarField::from_le_bytes_mod_order(&verifier_challenge[0..31]);

        Ok(verifier_challenge_fe)
    }

    pub fn sign_round1(
        parameters: &Parameters<C>,
        protocol_instance_entropy: [u8; 32],
    ) -> Result<ThresholdSchnorrMessage1, Error> {
        let random_scalar = Self::get_pseudorandom_scalar(protocol_instance_entropy);

        let prover_commitment = parameters.generator.mul(random_scalar).into_affine();
        let hash_commitment: [u8; 32] = Blake2s::digest(&serialize(&prover_commitment)).into();

        Ok(hash_commitment)
    }

    pub fn sign_round2(
        parameters: &Parameters<C>,
        protocol_instance_entropy: [u8; 32],
        _round1_messages: &[ThresholdSchnorrMessage1],
    ) -> Result<ThresholdSchnorrMessage2<C>, Error> {
        let random_scalar = Self::get_pseudorandom_scalar(protocol_instance_entropy);
        let prover_commitment = parameters.generator.mul(random_scalar).into_affine();

        Ok(prover_commitment)
    }

    pub fn sign_round3(
        parameters: &Parameters<C>,
        protocol_instance_entropy: [u8; 32],
        message_to_sign: &[u8],
        sk: &SecretKey<C>,
        public_keys: &[PublicKey<C>],
        round1_messages: &[ThresholdSchnorrMessage1],
        round2_messages: &[ThresholdSchnorrMessage2<C>],
    ) -> Result<ThresholdSchnorrMessage3<C>, ThresholdSchnorrError> {
        let aggregate_pk = public_keys.iter().fold(C::Affine::zero(), |acc, pk| (acc + pk).into_affine());

        let verifier_challenge = Self::compute_challenge(parameters, round1_messages, round2_messages, &aggregate_pk, message_to_sign)?;

        let random_scalar = Self::get_pseudorandom_scalar(protocol_instance_entropy);

        // k - xe;
        let prover_response = random_scalar - (verifier_challenge * sk);
        let signature = Signature { prover_response, verifier_challenge };

        Ok(signature)
    }

    pub fn aggregate(
        parameters: &Parameters<C>,
        message_to_sign: &[u8],
        public_keys: &[PublicKey<C>],
        round1_messages: &[ThresholdSchnorrMessage1],
        round2_messages: &[ThresholdSchnorrMessage2<C>],
        round3_messages: &[ThresholdSchnorrMessage3<C>],
    ) -> Result<Signature<C>, ThresholdSchnorrError> {
        let n = public_keys.len();
        if round1_messages.len() != n
            || round2_messages.len() != n
            || round3_messages.len() != n
        {
            return Err(ThresholdSchnorrError::InvalidInput);
        }

        let aggregate_pk = public_keys.iter().fold(C::Affine::zero(), |acc, pk| (acc + pk).into_affine());

        let verifier_challenge = Self::compute_challenge(parameters, round1_messages, round2_messages, &aggregate_pk, message_to_sign)?;
        for (i, sig) in round3_messages.iter().enumerate() {
            if sig.verifier_challenge != verifier_challenge {
                return Err(ThresholdSchnorrError::InvalidInput);
            }

            let public_key_times_verifier_challenge = public_keys[i].mul(verifier_challenge);

            let mut claimed_prover_commitment = parameters.generator.mul(sig.prover_response);
            claimed_prover_commitment += &public_key_times_verifier_challenge;
            let claimed_prover_commitment = claimed_prover_commitment.into_affine();

            if round2_messages[i] != claimed_prover_commitment {
                return Err(ThresholdSchnorrError::InvalidInput);
            }
        }

        let prover_response = round3_messages.iter().fold(C::ScalarField::zero(), |acc, sig| acc + sig.prover_response);

        Ok(Signature { prover_response, verifier_challenge })
    }
}

#[derive(Debug)]
pub enum ThresholdSchnorrError {
    /// Multi-purpose error type for describing invalid inputs
    InvalidInput,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::RngCore;

    fn get_entropy() -> [u8; 32] {
        let mut entropy = [0u8; 32];
        ark_std::rand::thread_rng().fill_bytes(&mut entropy);
        entropy
    }

    #[test]
    fn schnorr_sign_and_verify_should_succeed() {
        type C = ark_ed_on_bn254::EdwardsProjective;
        let entropy = get_entropy();
        let params = Schnorr::<C>::setup(entropy).unwrap();
        let (pk, sk) = Schnorr::<C>::keygen(&params, get_entropy()).unwrap();
        let message = b"hello schnorr";
        let sig = Schnorr::<C>::sign(&params, &sk, message, get_entropy()).unwrap();
        let valid = Schnorr::<C>::verify(&params, &pk, message, &sig).unwrap();
        assert!(valid);
    }

    #[test]
    fn schnorr_verify_should_fail_on_wrong_message() {
        type C = ark_ed_on_bn254::EdwardsProjective;
        let entropy = get_entropy();
        let params = Schnorr::<C>::setup(entropy).unwrap();
        let (pk, sk) = Schnorr::<C>::keygen(&params, get_entropy()).unwrap();
        let message = b"hello schnorr";
        let sig = Schnorr::<C>::sign(&params, &sk, message, get_entropy()).unwrap();
        let wrong_message = b"wrong message";
        let valid = Schnorr::<C>::verify(&params, &pk, wrong_message, &sig).unwrap();
        assert!(!valid);
    }

    #[test]
    fn thresholdschnorr_sign_rounds_and_aggregate_should_succeed() {
        type C = ark_ed_on_bn254::EdwardsProjective;
        let params = Schnorr::<C>::setup(get_entropy()).unwrap();
        let (pk1, sk1) = Schnorr::<C>::keygen(&params, get_entropy()).unwrap();
        let (pk2, sk2) = Schnorr::<C>::keygen(&params, get_entropy()).unwrap();
        let aggregate_pk = (pk1 + pk2).into_affine();
        let message = b"threshold schnorr";

        let protocol_instance_entropy1 = get_entropy();
        let protocol_instance_entropy2 = get_entropy();
        // Round 1
        let r1_msg1 = ThresholdSchnorr::<C>::sign_round1(&params, protocol_instance_entropy1).unwrap();
        let r1_msg2 = ThresholdSchnorr::<C>::sign_round1(&params, protocol_instance_entropy2).unwrap();

        // Round 2
        let r2_msg1 = ThresholdSchnorr::<C>::sign_round2(&params, protocol_instance_entropy1, &[r1_msg1, r1_msg2]).unwrap();
        let r2_msg2 = ThresholdSchnorr::<C>::sign_round2(&params, protocol_instance_entropy2, &[r1_msg1, r1_msg2]).unwrap();

        // Round 3
        let r3_msg1 = ThresholdSchnorr::<C>::sign_round3(
            &params,
            protocol_instance_entropy1,
            message,
            &sk1,
            &[pk1, pk2],
            &[r1_msg1, r1_msg2],
            &[r2_msg1, r2_msg2],
        ).unwrap();

        let r3_msg2 = ThresholdSchnorr::<C>::sign_round3(
            &params,
            protocol_instance_entropy2,
            message,
            &sk2,
            &[pk1, pk2],
            &[r1_msg1, r1_msg2],
            &[r2_msg1, r2_msg2],
        ).unwrap();

        // Aggregate
        let agg_sig = ThresholdSchnorr::<C>::aggregate(
            &params,
            message,
            &[pk1, pk2],
            &[r1_msg1, r1_msg2],
            &[r2_msg1, r2_msg2],
            &[r3_msg1, r3_msg2],
        ).unwrap();

        // Verify aggregate signature
        let valid = Schnorr::<C>::verify(&params, &aggregate_pk, message, &agg_sig).unwrap();
        assert!(valid);
    }
}
