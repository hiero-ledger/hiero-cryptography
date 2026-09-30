// SPDX-License-Identifier: Apache-2.0

use ark_bls12_381::{g1::Config as G1Config, g2::Config as G2Config, Bls12_381};
use ark_ec::hashing::{
    curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve,
};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{
    short_weierstrass::{Affine, Projective},
    AffineRepr, CurveGroup,
};
use ark_ff::{field_hashers::{DefaultFieldHasher, HashToField}, Field};
use ark_poly::{univariate::DensePolynomial, EvaluationDomain, Polynomial, Radix2EvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::collections::HashMap;
use ark_std::{ops::*, UniformRand};
use sha2::Sha256;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use zeroize::Zeroize;

// hinTS depends on the utils and kzg modules
use crate::kzg;
use crate::utils;
use crate::errors::*;
use crate::transcript::Transcript;

/// The size of input randomness
pub const RANDOM_SIZE: usize = 32;
/// Pairing friendly curve powering the hinTS scheme
pub type Curve = Bls12_381;
/// KZG polynomial commitment scheme
type KZG = kzg::KZG10<Curve, DensePolynomial<<Curve as Pairing>::ScalarField>>;
/// Common reference string for the hinTS scheme
pub type CRS = kzg::UniversalParams<Curve>;
/// Scalar Field
pub type F = ark_bls12_381::Fr;
/// Represents a point in G1 (affine coordinates)
pub type G1AffinePoint = Affine<G1Config>;
/// Represents a point in G2 (affine coordinates)
pub type G2AffinePoint = Affine<G2Config>;
/// Represents a point in G1 (projective coordinates)
pub type G1ProjectivePoint = Projective<G1Config>;
/// Represents a point in G2 (projective coordinates)
pub type G2ProjectivePoint = Projective<G2Config>;

/// Type denoting a partial signature, which is a G2 group element
pub type PartialSignature = G2AffinePoint;

/// Type denoting public key, which is a G1 group element
pub type PublicKey = G1AffinePoint;
/// Type denoting a signer's weight, which is just a scalar value
pub type Weight = F;

/// Type denoting secret key, which is just a scalar value
#[derive(Clone, Debug, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
pub struct SecretKey {
    secret: F,
    pop: ProofOfPossesion,
}

/// Non-interactive proof of knowledge of discrete log, using Fiat-Shamir transform
#[derive(Debug, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProofOfPossesion {
    pub commitment: G1AffinePoint,
    pub challenge: F,
    pub response: F,
}

impl std::ops::Deref for SecretKey {
    type Target = F;
    fn deref(&self) -> &Self::Target {
        &self.secret
    }
}

impl std::borrow::Borrow<F> for SecretKey {
    fn borrow(&self) -> &F {
        &self.secret
    }
}

impl std::borrow::Borrow<ProofOfPossesion> for SecretKey {
    fn borrow(&self) -> &ProofOfPossesion {
        &self.pop
    }
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.secret.zeroize();
        self.pop.commitment.zeroize();
        self.pop.challenge.zeroize();
        self.pop.response.zeroize();
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

macro_rules! check_or_return_false {
    ($cond:expr) => {
        if !$cond {
            return Ok(false);
        }
    };
}


#[derive(Clone, Debug, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
/// hinTS aggregate signature, in the optimized layout of Sec 3.4.3 of the whitepaper
pub struct ThresholdSignature {
    /// aggregate public key (aPK in the paper)
    agg_pk: G1AffinePoint,
    /// aggregate weight (w in the paper)
    agg_weight: Weight,
    /// aggregate signature
    agg_sig: G2AffinePoint,

    /// commitment to the bitmap polynomial ([B(τ)]_1 in the paper)
    b_of_tau_com: G1AffinePoint,
    /// commitment to the Q_x polynomial ([Q_x(τ)]_1 in the paper)
    qx_of_tau_com: G1AffinePoint,
    /// commitment to the Q_x polynomial ([Q_x(τ) . τ ]_1 in the paper)
    qx_of_tau_mul_tau_com: G1AffinePoint,
    /// commitment to the Q_z polynomial ([Q_z(τ)]_1 in the paper)
    qz_of_tau_com: G1AffinePoint,
    /// commitment to the ParSum polynomial ([ParSum(τ)]_1 in the paper)
    parsum_of_tau_com: G1AffinePoint,
    /// commitment to the merged quotient polynomial ([Q^mrg(τ)]_1 in the paper)
    q_mrg_of_tau_com: G1AffinePoint,

    /// opening proof at x = r for Q = Q^mrg + χ_op·ParSum + χ_op^2·B + χ_op^3·W
    opening_proof_r: G1AffinePoint,
    /// proof for the ParSum opening at x = r / ω
    opening_proof_r_div_ω: G1AffinePoint,

    /// polynomial evaluation of ParSum(x) at x = r
    parsum_of_r: F,
    /// polynomial evaluation of ParSum(x) at x = r / ω
    parsum_of_r_div_ω: F,
    /// evaluation at x = r of the verification key's weight polynomial W(x)
    w_of_r: F,
    /// polynomial evaluation of bitmap B(x) at x = r
    b_of_r: F,
    /// polynomial evaluation of the merged quotient Q^mrg(x) at x = r
    q_mrg_of_r: F,
}

#[derive(Clone, Debug, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
/// Hint contains all material output by a party during the setup phase
pub struct ExtendedPublicKey {
    /// index in the address book
    i: usize,
    /// universe size (power of 2) for which this extended public key is generated
    n: usize,
    /// public key pk = [sk]_1
    pk_i: PublicKey,
    /// proof of knowledge of the secret key sk_i
    pok_i: ProofOfPossesion,
    /// [ sk_i L_i(τ) ]_1
    sk_i_l_i_of_tau_com_1: G1AffinePoint,
    /// [ sk_i L_i(τ) ]_2
    sk_i_l_i_of_tau_com_2: G2AffinePoint,
    /// qz_i_terms[i] = [ sk_i * ((L_i^2(τ) - L_i(τ)) / Z(τ)) ]_1
    /// \forall j != i, qz_i_terms[j] = [ sk_i * (L_i(τ) * L_j(τ) / Z(τ)) ]_1
    qz_i_terms: Vec<G1AffinePoint>,
    /// [ sk_i ((L_i(τ) - L_i(0)) / τ ]_1
    qx_i_term: G1AffinePoint,
    /// [ sk_i ((L_i(τ) - L_i(0))]_1
    qx_i_term_mul_tau: G1AffinePoint,
}

#[derive(Clone, Debug, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
/// AggregationKey contains all material needed by Prover to produce a hinTS proof
pub struct AggregationKey {
    /// number of parties in the universe plus one (must be a power of 2)
    n: usize,
    /// weights has all parties' weights, where weights[i] is party i's weight
    weights: Vec<Weight>,
    /// pks contains all parties' public keys, where pks[i] is g^sk_i
    pks: Vec<PublicKey>,
    /// qz_terms contains pre-processed hints for the Q_z polynomial.
    /// qz_terms[i] has the following form:
    /// [sk_i * (L_i(\tau)^2 - L_i(\tau)) / Z(\tau) +
    /// \Sigma_{j} sk_j * (L_i(\tau) L_j(\tau)) / Z(\tau)]_1
    qz_terms: Vec<G1AffinePoint>,
    /// qx_terms contains pre-processed hints for the Q_x polynomial.
    /// qx_terms[i] has the form [ sk_i * (L_i(\tau) - L_i(0)) / x ]_1
    qx_terms: Vec<G1AffinePoint>,
    /// qx_mul_tau_terms contains pre-processed hints for the Q_x * x polynomial.
    /// qx_mul_tau_terms[i] has the form [ sk_i * (L_i(\tau) - L_i(0)) ]_1
    qx_mul_tau_terms: Vec<G1AffinePoint>,
}

#[derive(Clone, Debug, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
/// structure containing the verification key required to verify a hinTS signature
pub struct VerificationKey {
    /// the universe has n - 1 parties (where n is a power of 2)
    n: usize,
    /// total weight of all signers
    total_weight: Weight,
    /// first G1 element from the KZG CRS (for zeroth power of tau)
    g_0: G1AffinePoint,
    /// first G2 element from the KZG CRS (for zeroth power of tau)
    h_0: G2AffinePoint,
    /// second G1 element from the KZG CRS (for first power of tau)
    h_1: G2AffinePoint,
    /// commitment to the L_{n-1} polynomial
    l_n_minus_1_of_tau_com: G1AffinePoint,
    /// commitment to the W polynomial
    w_of_tau_com: G1AffinePoint,
    /// commitment to the SK polynomial
    sk_of_tau_com: G2AffinePoint,
    /// commitment to the vanishing polynomial Z(x) = x^n - 1
    z_of_tau_com: G2AffinePoint,
}

/// checks whether the CRS carries enough powers in both towers for a universe of size n.
///
/// Phrased as `n >= len` rather than `len - 1 < n` because release builds have overflow
/// checks off: an empty tower wraps the subtraction to usize::MAX, which makes the check
/// pass for every n. Both towers matter since we commit in G1 and G2.
fn crs_supports(crs: &CRS, n: usize) -> bool {
    n < crs.powers_of_g.len() && n < crs.powers_of_h.len()
}

/// checks whether an aggregation key's parallel vectors all agree with its n.
///
/// n bounds the party index for every one of these vectors, and consumers index them by
/// party id having only range-checked against n. Deserialization reads n and the vectors
/// as independent fields, so nothing else ties them together.
fn aggregation_key_is_well_formed(ak: &AggregationKey) -> bool {
    ak.weights.len() == ak.n
        && ak.pks.len() == ak.n
        && ak.qz_terms.len() == ak.n
        && ak.qx_terms.len() == ak.n
        && ak.qx_mul_tau_terms.len() == ak.n
}

pub struct HinTS;

impl HinTS {
    /// generates a random secret key using a PRNG seeded by the input entropy
    pub fn keygen(
        seed: [u8; 32]
    ) -> Result<SecretKey, HinTSError> {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

        // let us extract two random seeds from the PRNG
        // for generating the secret and proof of possession
        let mut secret_seed = [0u8; 32];
        let mut proof_seed = [0u8; 32];
        rng.fill_bytes(&mut secret_seed);
        rng.fill_bytes(&mut proof_seed);

        let secret = F::rand(&mut rand_chacha::ChaCha8Rng::from_seed(secret_seed));
        let pop = generate_proof_of_knowledge(&secret, proof_seed)?;
        Ok(SecretKey { secret, pop })
    }

    /// generates the extended public key (a.k.a. hint) for signer with
    /// secret key sk and index i within a universe of n-1 signers
    pub fn hint_gen(
        crs: &CRS,
        n: usize,
        i: usize,
        sk_with_pop: &SecretKey
    ) -> Result<ExtendedPublicKey, HinTSError> {
        // let us first perform sanity checks on the input

        // we require n to be a power of 2, greater than 1
        if !utils::is_n_valid(n) {
            return Err(HinTSError::InvalidNetworkSize(n));
        }

        // obviously, i must be less than n
        if i >= n {
            return Err(HinTSError::InvalidInput(
                format!("Invalid index i = {} greater than n = {}", i, n))
            );
        }

        // CRS must be large enough to support the operation
        // NOTE: CRS must also be valid, but we assume that here!
        if !crs_supports(crs, n) {
            return Err(HinTSError::InsufficientCRS(n));
        }

        let sk = &sk_with_pop.secret;

        //let us compute the q1 term
        let l_i_of_x = utils::lagrange_poly(n, i).ok_or(
            HinTSError::CryptographyCatastrophe(
                format!("Unable to compute Lagrange<n,i>(x) for i = {}, n = {}", i, n)
            )
        )?;
        let z_of_x = utils::compute_vanishing_poly(n);

        let mut qz_terms = vec![];
        //let us compute the cross terms of q1
        for j in 0..n {
            let num: DensePolynomial<F>; // = compute_constant_poly(&F::from(0));
            if i == j {
                num = l_i_of_x.mul(&l_i_of_x).sub(&l_i_of_x);
            } else {
                //cross-terms
                let l_j_of_x = utils::lagrange_poly(n, j).ok_or(
                    HinTSError::CryptographyCatastrophe(
                        format!("Unable to compute Lagrange<n,j>(x) for j = {}, n = {}", j, n)
                    )
                )?;
                num = l_j_of_x.mul(&l_i_of_x);
            }

            let f = num.div(&z_of_x);
            let sk_times_f = utils::poly_eval_mult_c(&f, sk);

            let com = KZG::commit_g1(&crs, &sk_times_f)?;

            qz_terms.push(com);
        }

        let l_i_of_0 = l_i_of_x.evaluate(&F::from(0));
        let l_i_of_0_poly = utils::compute_constant_poly(&l_i_of_0);

        //numerator is l_i(x) - l_i(0)
        let num = l_i_of_x.sub(&l_i_of_0_poly);
        //denominator is x
        let den = utils::compute_x_monomial();
        //qx_term = sk_i * (l_i(x) - l_i(0)) / x
        let qx_term = utils::poly_eval_mult_c(&num.div(&den), sk);
        //qx_term_mul_tau = sk_i * (l_i(x) - l_i(0)) / x
        let qx_term_mul_tau = utils::poly_eval_mult_c(&num, sk);
        //qx_term_com = [ sk_i * (l_i(τ) - l_i(0)) / τ ]_1
        let qx_term_com = KZG::commit_g1(&crs, &qx_term)?;
        //qx_term_mul_tau_com = [ sk_i * (l_i(τ) - l_i(0)) ]_1
        let qx_term_mul_tau_com = KZG::commit_g1(&crs, &qx_term_mul_tau)?;

        //release my public key
        let sk_as_poly = utils::compute_constant_poly::<F>(sk);
        let pk = KZG::commit_g1(&crs, &sk_as_poly)?;

        let sk_times_l_i_of_x = utils::poly_eval_mult_c(&l_i_of_x, sk);
        let com_sk_l_i_g1 = KZG::commit_g1(&crs, &sk_times_l_i_of_x)?;
        let com_sk_l_i_g2 = KZG::commit_g2(&crs, &sk_times_l_i_of_x)?;

        Ok(ExtendedPublicKey {
            i: i,
            n: n,
            pk_i: pk,
            pok_i: sk_with_pop.pop.clone(),
            sk_i_l_i_of_tau_com_1: com_sk_l_i_g1,
            sk_i_l_i_of_tau_com_2: com_sk_l_i_g2,
            qz_i_terms: qz_terms,
            qx_i_term: qx_term_com,
            qx_i_term_mul_tau: qx_term_mul_tau_com,
        })
    }

    /// verifies whether the extended public key (a.k.a. hint) is well-formed for the
    /// given universe size n and index i; note that errors indicate incorrect inputs
    /// while a return value of false indicates that the hint is maliciously crafted
    pub fn verify_hint(
        crs: &CRS,
        n: usize,
        i: usize,
        hint: &ExtendedPublicKey
    ) -> Result<bool, HinTSError> {
        // sanity check on the inputs

        // we require n to be a power of 2, greater than 1
        if !utils::is_n_valid(n) {
            return Err(HinTSError::InvalidNetworkSize(n));
        }

        // obviously, i must be less than n
        if i >= n {
            return Err(HinTSError::InvalidInput(
                format!("Invalid index i = {} greater than n = {}", i, n))
            );
        }

        // CRS must be large enough to support the operation
        // NOTE: CRS must also be valid, but we assume that here!
        if !crs_supports(crs, n) {
            return Err(HinTSError::InsufficientCRS(n));
        }

        // return false immediately if some simple checks dont hold on the hint
        check_or_return_false!(hint.i == i);
        check_or_return_false!(hint.n == n);
        check_or_return_false!(n == hint.qz_i_terms.len());
        check_or_return_false!(!hint.pk_i.is_zero());
        check_or_return_false!(!hint.sk_i_l_i_of_tau_com_1.is_zero());
        check_or_return_false!(!hint.sk_i_l_i_of_tau_com_2.is_zero());
        check_or_return_false!(!hint.qx_i_term.is_zero());
        check_or_return_false!(!hint.qx_i_term_mul_tau.is_zero());
        check_or_return_false!(hint.qz_i_terms.iter().all(|point| !point.is_zero()));

        // verify proof of possession of the secret key
        check_or_return_false!(verify_proof_of_knowledge(&hint.pok_i, &hint.pk_i)?);

        //e([sk_i L_i(τ)]1, [1]2) = e([sk_i]1, [L_i(τ)]2)
        let l_i_of_x = utils::lagrange_poly(n, i).ok_or(
            HinTSError::CryptographyCatastrophe(
                format!("Unable to compute Lagrange<n,i>(x) for i = {}, n = {}", i, n)
            )
        )?;
        let z_of_x = utils::compute_vanishing_poly(n);

        let l_i_of_tau_com = KZG::commit_g2(&crs, &l_i_of_x)?;
        let lhs = <Curve as Pairing>::pairing(hint.sk_i_l_i_of_tau_com_1, crs.powers_of_h[0]);
        let rhs = <Curve as Pairing>::pairing(hint.pk_i, l_i_of_tau_com);
        check_or_return_false!(lhs == rhs);

        //e([1]_1, [sk_i L_i(τ)]_2) = e([sk_i]_1, [L_i(τ)]_2)
        let lhs2 = <Curve as Pairing>::pairing(crs.powers_of_g[0], hint.sk_i_l_i_of_tau_com_2);
        check_or_return_false!(lhs2 == rhs);

        for j in 0..n {
            let num: DensePolynomial<F>;
            if i == j {
                num = l_i_of_x.clone().mul(&l_i_of_x).sub(&l_i_of_x);
            } else {
                //cross-terms
                let l_j_of_x = utils::lagrange_poly(n, j).ok_or(
                    HinTSError::CryptographyCatastrophe(
                        format!("Unable to compute Lagrange<n,j>(x) for j = {}, n = {}", j, n)
                    )
                )?;
                num = l_j_of_x.mul(&l_i_of_x);
            }
            let f = num.div(&z_of_x);

            //f = li^2 - l_i / z or li lj / z
            let f_com = KZG::commit_g2(&crs, &f)?;

            let lhs = <Curve as Pairing>::pairing(hint.qz_i_terms[j], crs.powers_of_h[0]);
            let rhs = <Curve as Pairing>::pairing(hint.pk_i, f_com);
            check_or_return_false!(lhs == rhs);
        }

        let l_i_of_0 = l_i_of_x.evaluate(&F::from(0));
        let l_i_of_0_poly = utils::compute_constant_poly(&l_i_of_0);

        //numerator is l_i(x) - l_i(0)
        let num = l_i_of_x.sub(&l_i_of_0_poly);
        //denominator is x
        let den = utils::compute_x_monomial();

        //qx_term = (l_i(x) - l_i(0)) / x
        let qx_term = &num.div(&den);
        //qx_term_com = [ sk_i * (l_i(τ) - l_i(0)) / τ ]_1
        let qx_term_com = KZG::commit_g2(&crs, &qx_term)?;
        let lhs = <Curve as Pairing>::pairing(hint.qx_i_term, crs.powers_of_h[0]);
        let rhs = <Curve as Pairing>::pairing(hint.pk_i, qx_term_com);
        check_or_return_false!(lhs == rhs);

        //qx_term_mul_tau = (l_i(x) - l_i(0))
        let qx_term_mul_tau = &num;
        //qx_term_mul_tau_com = [ (l_i(τ) - l_i(0)) ]_1
        let qx_term_mul_tau_com = KZG::commit_g2(&crs, &qx_term_mul_tau)?;
        let lhs = <Curve as Pairing>::pairing(hint.qx_i_term_mul_tau, crs.powers_of_h[0]);
        let rhs = <Curve as Pairing>::pairing(hint.pk_i, qx_term_mul_tau_com);
        check_or_return_false!(lhs == rhs);

        Ok(true)
    }

    /// preprocesses all signers' extended public keys and weights,
    /// and outputs the network's verification key and aggregation key
    pub fn preprocess(
        n: usize,
        crs: &CRS,
        signer_info: &HashMap<usize, (Weight, ExtendedPublicKey)>,
    ) -> Result<(VerificationKey, AggregationKey), HinTSError> {
        // sanity check on the inputs

        // we require n to be a power of 2, greater than 1
        if !utils::is_n_valid(n) {
            return Err(HinTSError::InvalidNetworkSize(n));
        }

        // we need at least one reserved location for hinTS
        if signer_info.len() + 1 > n {
            return Err(HinTSError::InvalidNetworkSize(n));
        }

        // the check above only counts the entries; index n-1 is the location reserved above, and
        // aggregate later overwrites it, so a party sitting there yields keys that verify nothing
        if let Some(&party_id) = signer_info.keys().find(|&&i| i >= n - 1) {
            return Err(HinTSError::InvalidInput(format!(
                "party index {} is not below the reserved index {}",
                party_id,
                n - 1
            )));
        }

        // CRS must be large enough to support the operation
        // NOTE: CRS must also be valid, but we assume that here!
        if !crs_supports(crs, n) {
            return Err(HinTSError::InsufficientCRS(n));
        }

        let mut weights: Vec<Weight> = Vec::new();
        let mut epks: Vec<ExtendedPublicKey> = Vec::new();
        for i in 0..n {
            if let Some((weight, hint)) = signer_info.get(&i) {
                if hint.n != n {
                    return Err(HinTSError::InvalidInput(
                        format!("Invalid hint: got hint.n = {}, expected n = {}", hint.n, n))
                    );
                }
                if ! Self::verify_hint(crs, n, i, hint)? {
                    return Err(HinTSError::InvalidInput(
                        format!("Invalid hint: hint verification failed for i = {}", i))
                    );
                }
                weights.push(*weight);
                epks.push(hint.clone());
            } else {
                weights.push(F::from(0));
                let zero = F::from(0);
                let zero_sk = SecretKey {
                    secret: zero,
                    pop: generate_proof_of_knowledge(&zero, [0u8; RANDOM_SIZE])?,
                };
                epks.push(Self::hint_gen(crs, n, i, &zero_sk)?);
            }
        }

        let w_of_x = utils::interpolate_poly_over_mult_subgroup(&weights).ok_or(
            HinTSError::CryptographyCatastrophe(
                format!("Unable to construct Radix2EvaluationDomain for n = {}", weights.len())
            )
        )?;

        //allocate space to collect setup material from all n-1 parties
        let mut qz_contributions: Vec<Vec<G1AffinePoint>> = vec![Default::default(); n];
        let mut qx_contributions: Vec<G1AffinePoint> = vec![Default::default(); n];
        let mut qx_mul_tau_contributions: Vec<G1AffinePoint> = vec![Default::default(); n];
        let mut pks: Vec<G1AffinePoint> = vec![Default::default(); n];
        let mut sk_l_of_tau_coms: Vec<G2AffinePoint> = vec![Default::default(); n];

        for hint in epks {
            //extract necessary items for pre-processing
            qz_contributions[hint.i] = hint.qz_i_terms.clone();
            qx_contributions[hint.i] = hint.qx_i_term.clone();
            qx_mul_tau_contributions[hint.i] = hint.qx_i_term_mul_tau.clone();
            pks[hint.i] = hint.pk_i.clone();
            sk_l_of_tau_coms[hint.i] = hint.sk_i_l_i_of_tau_com_2.clone();
        }

        let z_of_x = utils::compute_vanishing_poly(n);
        let l_n_minus_1_of_x = utils::lagrange_poly(n, n - 1).ok_or(
            HinTSError::CryptographyCatastrophe(
                format!("Unable to compute Lagrange<n,i>(x) for i = {}, n = {}", n - 1, n)
            )
        )?;

        let total_weight = weights.iter().fold(F::from(0), |acc, &x| acc + x);

        let vk = VerificationKey {
            n: n,
            total_weight: total_weight,
            g_0: crs.powers_of_g[0],
            h_0: crs.powers_of_h[0],
            h_1: crs.powers_of_h[1],
            l_n_minus_1_of_tau_com: KZG::commit_g1(&crs, &l_n_minus_1_of_x)?,
            w_of_tau_com: KZG::commit_g1(&crs, &w_of_x)?,
            sk_of_tau_com: add::<G2AffinePoint>(sk_l_of_tau_coms),
            z_of_tau_com: KZG::commit_g2(&crs, &z_of_x)?,
        };

        let ak = AggregationKey {
            n: n,
            weights: weights,
            pks: pks,
            qz_terms: preprocess_qz_contributions(&qz_contributions),
            qx_terms: qx_contributions,
            qx_mul_tau_terms: qx_mul_tau_contributions,
        };

        // we are the only producer of aggregation keys, so a mismatch here is our own bug;
        // fail before it reaches state, where it would be permanent
        if !aggregation_key_is_well_formed(&ak) {
            return Err(HinTSError::CryptographyCatastrophe(
                format!("preprocess produced an inconsistent aggregation key for n = {}", n))
            );
        }

        Ok((vk, ak))
    }

    /// signs a message using the signer's secret key, producing a partial signature
    pub fn sign(
        msg: &[u8],
        sk: &SecretKey
    ) -> Result<PartialSignature, HinTSError> {
        Ok(hash_to_g2(msg)?.mul(sk.secret).into_affine())
    }

    /// verifies the partial signature under the signer's public key
    pub fn partial_verify(
        msg: &[u8],
        ak: &AggregationKey,
        party_id: usize,
        sig: &PartialSignature
    ) -> Result<bool, HinTSError> {
        // we require n to be a power of 2, greater than 1
        if !utils::is_n_valid(ak.n) {
            return Err(HinTSError::InvalidNetworkSize(ak.n));
        }

        // the range check below is against n, so n must actually describe the key
        if !aggregation_key_is_well_formed(ak) {
            return Err(HinTSError::InvalidInput(
                format!("malformed aggregation key: n = {}", ak.n))
            );
        }

        // party_id can only be between 0 and n-2, inclusive
        if party_id >= ak.n - 1 { // usize ensures non-negative
            return Err(HinTSError::InvalidInput(
                format!("signer_id {} out of range", party_id))
            );
        }

        let lhs = <Curve as Pairing>::pairing(ak.pks[party_id], hash_to_g2(msg)?);
        let rhs = <Curve as Pairing>::pairing(G1AffinePoint::generator(), sig);
        Ok(lhs == rhs)
    }

    /// verifies the list of partial signatures from a list of signers
    pub fn partial_verify_batch(
        msg: &[u8],
        ak: &AggregationKey,
        signer_ids: impl AsRef<[usize]>,
        signatures: impl AsRef<[PartialSignature]>,
    ) -> Result<bool, HinTSError> {
        // we require n to be a power of 2, greater than 1
        if !utils::is_n_valid(ak.n) {
            return Err(HinTSError::InvalidNetworkSize(ak.n));
        }

        // the range check below is against n, so n must actually describe the key
        if !aggregation_key_is_well_formed(ak) {
            return Err(HinTSError::InvalidInput(
                format!("malformed aggregation key: n = {}", ak.n))
            );
        }

        // check that the two lists are of the same size
        if signer_ids.as_ref().len() != signatures.as_ref().len() {
            return Err(HinTSError::InvalidInput(
                "signer_ids and signatures must be of the same size".to_string(),
            ));
        }

        // an empty batch verifies vacuously: add() returns the identity in both groups, so the
        // pairing check below collapses to 1_GT == 1_GT and we would report success without
        // having verified anything. Wrong direction to fail in.
        if signer_ids.as_ref().is_empty() {
            return Err(HinTSError::InvalidInput(
                "signer_ids must not be empty".to_string(),
            ));
        }

        // ensure all signer_ids are within the valid range
        if signer_ids.as_ref().iter().any(|&id| id >= ak.n - 1) {
            return Err(HinTSError::InvalidInput(
                "One or more signer_ids are out of range".to_string(),
            ));
        }

        // compute aggregate public key of all signers
        let apk = add::<G1AffinePoint>(signer_ids.as_ref().iter().map(|&x| ak.pks[x]));
        // compute aggregate signature
        let agg_sig = add::<G2AffinePoint>(signatures.as_ref().iter().map(|sig| sig.clone()));

        let lhs = <Curve as Pairing>::pairing(apk, hash_to_g2(msg)?);
        let rhs = <Curve as Pairing>::pairing(G1AffinePoint::generator(), agg_sig);
        Ok(lhs == rhs)
    }

    /// aggregates partial signatures to construct a threshold signature
    pub fn aggregate(
        crs: &CRS,
        ak: &AggregationKey,
        vk: &VerificationKey,
        partial_signatures: &HashMap<usize, PartialSignature>,
    ) -> Result<ThresholdSignature, HinTSError> {
        let n = ak.n;

        // everything below sizes buffers and indexes the key's vectors off n
        if !aggregation_key_is_well_formed(ak) {
            return Err(HinTSError::InvalidInput(
                format!("malformed aggregation key: n = {}", n))
            );
        }

        // CRS must be large enough to support the operation
        // NOTE: CRS must also be valid, but we assume that here!
        if !crs_supports(crs, n) {
            return Err(HinTSError::InsufficientCRS(n));
        }

        // we require n to be a power of 2
        if !utils::is_n_valid(n) {
            return Err(HinTSError::InvalidNetworkSize(n));
        }

        let witness = assemble_witness(ak, partial_signatures)?;
        let (π, exact) = prove(crs, ak, vk, &witness)?;

        // an honest witness satisfies all four relations on the whole domain, so a remainder
        // means the inputs disagree with each other (e.g. an aggregation key that gives the
        // reserved slot a weight); refuse, rather than emit a signature that cannot verify
        if !exact {
            return Err(HinTSError::InvalidInput(
                "aggregation inputs do not satisfy the hinTS relations".to_string()
            ));
        }

        Ok(π)
    }

    /// verifies whether the threshold signature is valid and
    /// satisfies the desired threshold fraction
    pub fn verify(
        msg: &[u8],
        vk: &VerificationKey,
        π: &ThresholdSignature,
        fraction: (F, F), // e.g. (1,3) to denote 1/3 threshold
    ) -> Result<bool, HinTSError> {
        // Every other entry point checks this; verify was the exception. n = 0 divides by
        // zero below, and a non-power-of-two n makes the evaluation domain disagree with the
        // vanishing polynomial we compute from it.
        check_or_return_false!(utils::is_n_valid(vk.n));

        // Zero aggregate values satisfy the BLS pairing equation trivially.
        check_or_return_false!(!π.agg_pk.is_zero());
        check_or_return_false!(!π.agg_sig.is_zero());

        // check that the threshold is satisfied
        let (numerator, denominator) = fraction;

        // The threshold verification uses a strict comparison "greater than" to prevent network
        // partition where two halves of a disconnected network could both produce valid signatures
        // with a threshold of 1/2 if verified via a non-strict "greater than or equal to":
        check_or_return_false!(denominator * π.agg_weight > numerator * vk.total_weight);

        // verify the signature first
        check_or_return_false!(bls_check(msg, vk, π)?);

        // compute nth root of unity
        let ω: F = utils::nth_root_of_unity(vk.n).ok_or(
            HinTSError::CryptographyCatastrophe(
                format!("Unable to construct Radix2EvaluationDomain for n = {}", vk.n)
            )
        )?;

        // the three challenges, drawn exactly as the aggregator drew them
        let (χ_q, r, χ_op) = derive_challenges(vk, π)?;

        check_or_return_false!(merged_relation_check(vk, π, ω, χ_q, r));
        check_or_return_false!(opening_at_r_check(vk, π, r, χ_op));
        check_or_return_false!(opening_at_r_div_ω_check(vk, π, r / ω));

        // e([Q_x(τ)]_1, [τ]_2) appears in both remaining checks, so compute it once
        let e_qx_tau = <Curve as Pairing>::pairing(&π.qx_of_tau_com, &vk.h_1);
        check_or_return_false!(sumcheck_check(vk, π, &e_qx_tau));
        check_or_return_false!(degree_check(vk, π, &e_qx_tau));

        Ok(true)
    }
}

/// domain separators for the three Fiat-Shamir rounds of the aggregate signature (Sec 3.4.3
/// of the whitepaper); none is shared with the four-quotient layout that preceded it
const DST_QUOTIENT_MERGE: &[u8] = b"HINTS_SIG_BLS12381:FIAT_SHAMIR_V2_QUOTIENT_MERGE";
const DST_EVALUATION_POINT: &[u8] = b"HINTS_SIG_BLS12381:FIAT_SHAMIR_V2_EVALUATION_POINT";
const DST_OPENING_BATCH: &[u8] = b"HINTS_SIG_BLS12381:FIAT_SHAMIR_V2_OPENING_BATCH";

/// What the aggregator proves: the bitmap and running sums over the n slots, and the
/// aggregate values computed from the signers' public material. `aggregate` assembles it
/// honestly from the partial signatures; tests hand `prove` tampered witnesses instead, to
/// check that the verifier rejects each way of cheating.
#[derive(Clone)]
struct Witness {
    /// b_i for each slot; the reserved slot n - 1 is always set
    bitmap: Vec<F>,
    /// inclusive running sums of b_i · w_i, where the reserved slot carries weight -w,
    /// so the sum returns to zero there
    parsum: Vec<F>,
    /// the claimed aggregate weight w
    agg_weight: F,
    /// aggregate public key, scaled by 1/n
    agg_pk: G1AffinePoint,
    /// aggregate signature, scaled by 1/n
    agg_sig: G2AffinePoint,
    /// [Q_z(τ)]_1, summed from the aggregation key's pre-processed hints
    qz_of_tau_com: G1AffinePoint,
    /// [Q_x(τ)]_1, summed likewise
    qx_of_tau_com: G1AffinePoint,
    /// [Q_x(τ) · τ]_1, summed likewise
    qx_of_tau_mul_tau_com: G1AffinePoint,
}

/// assembles the witness for a set of partial signatures, exactly as an honest aggregator does
fn assemble_witness(
    ak: &AggregationKey,
    partial_signatures: &HashMap<usize, PartialSignature>,
) -> Result<Witness, HinTSError> {
    let n = ak.n;
    let n_inv = F::from(1) / F::from(n as u64);

    // compute bitmap based on entries in partial_signatures
    let mut bitmap: Vec<F> = vec![F::from(0); n];
    for (i, _sig) in partial_signatures.iter() {
        // Validate party ID is within bounds: 0 <= i <= n - 2
        // Recall that we reserve location n - 1 for the hinTS scheme,
        // so the last valid signer ID is n - 2
        if *i > (n - 2) {
            return Err(HinTSError::InvalidInput(
                format!("Invalid party ID {}: must be <= n - 2 ({})", i, n - 2)
            ));
        }
        bitmap[*i] = F::from(1);
    }

    //compute sum of weights of active signers
    let agg_weight = bitmap
        .iter()
        .zip(ak.weights.iter())
        .fold(F::from(0), |acc, (&b, &w)| acc + (b * w));

    // the reserved slot is always set and carries weight -w, so that the running sum over
    // all n slots returns to zero exactly there
    bitmap[n - 1] = F::from(1);
    let mut weights = ak.weights.clone();
    weights[n - 1] = F::from(0) - agg_weight;
    let parsum = running_sums(&weights, &bitmap);

    // aggregate pubkey is the sum of all active public keys, multiplied by n_inv
    let agg_pk = inner_product(&ak.pks, &bitmap).mul(n_inv).into_affine();

    // aggregate sig is the sum of all partial signatures, multiplied by n_inv
    let agg_sig = add::<G2AffinePoint>(partial_signatures.values().cloned())
        .mul(n_inv)
        .into_affine();

    let qz_of_tau_com = inner_product(&ak.qz_terms, &bitmap);
    let qx_of_tau_com = inner_product(&ak.qx_terms, &bitmap);
    let qx_of_tau_mul_tau_com = inner_product(&ak.qx_mul_tau_terms, &bitmap);

    Ok(Witness {
        bitmap,
        parsum,
        agg_weight,
        agg_pk,
        agg_sig,
        qz_of_tau_com,
        qx_of_tau_com,
        qx_of_tau_mul_tau_com,
    })
}

/// computes the signature for a witness (Sec 3.4.3 of the whitepaper). Returns it together
/// with whether the merged relation divided exactly by Z(X), which it does for every honest
/// witness; `aggregate` refuses to emit a signature when it does not.
fn prove(
    crs: &CRS,
    ak: &AggregationKey,
    vk: &VerificationKey,
    witness: &Witness,
) -> Result<(ThresholdSignature, bool), HinTSError> {
    let n = ak.n;
    let domain = Radix2EvaluationDomain::<F>::new(n).ok_or(
        HinTSError::CryptographyCatastrophe(
            format!("Unable to construct Radix2EvaluationDomain for n = {}", n)
        )
    )?;
    let ω: F = domain.group_gen;

    let b_of_x = interpolate(&witness.bitmap)?;
    let psw_of_x = interpolate(&witness.parsum)?;
    // the polynomial vk.w_of_tau_com commits to; the reserved slot carries no weight in it
    let w_of_x = interpolate(&ak.weights)?;
    let l_n_minus_1_of_x = utils::lagrange_poly(n, n - 1).ok_or(
        HinTSError::CryptographyCatastrophe(
            format!("Unable to compute Lagrange<n,i>(x) for i = {}, n = {}", n - 1, n)
        )
    )?;

    let b_of_tau_com = KZG::commit_g1(crs, &b_of_x)?;
    let parsum_of_tau_com = KZG::commit_g1(crs, &psw_of_x)?;

    // Round 1: χ_Q is drawn before the merged quotient exists
    let mut transcript = Transcript::new();
    absorb_round_1(
        &mut transcript,
        vk,
        &witness.agg_pk,
        &witness.agg_weight,
        &b_of_tau_com,
        &parsum_of_tau_com,
        &witness.qx_of_tau_com,
        &witness.qz_of_tau_com,
        &witness.qx_of_tau_mul_tau_com,
    )?;
    let χ_q: F = transcript.challenge(DST_QUOTIENT_MERGE);

    // The four relations of Sec 3.4.3, each of which must vanish on the whole domain:
    //   P1 = PS(X) - PS(X/ω) - (W(X) - w·L_{n-1}(X))·B(X)   the running sum steps by b_i·w_i
    //   P2 = B(X)·B(X) - B(X)                              the bitmap is binary
    //   P3 = L_{n-1}(X)·PS(X)                              the running sum ends at zero
    //   P4 = L_{n-1}(X)·(B(X) - 1)                         the reserved slot is set
    // The paper numbers slots from 1 and its running sum is exclusive (zero at the first
    // slot, hence L_1·PS). Ours is inclusive: the reserved slot's weight -w is the last term,
    // so the sum returns to zero at the reserved slot itself, and P3 and P4 share L_{n-1}.
    // Our running sum at slot i is the paper's at slot i + 2, i.e. its next slot, which is
    // also why the recurrence looks back to X/ω and ParSum is opened at r/ω rather than rω.
    let psw_of_x_div_ω = utils::poly_domain_mult_ω(&psw_of_x, &(F::from(1) / ω));
    let w_adj_of_x = &w_of_x - &utils::poly_eval_mult_c(&l_n_minus_1_of_x, &witness.agg_weight);
    let one = utils::compute_constant_poly(&F::from(1));
    let p1_of_x = &(&psw_of_x - &psw_of_x_div_ω) - &(&w_adj_of_x * &b_of_x);
    let p2_of_x = &(&b_of_x * &b_of_x) - &b_of_x;
    let p3_of_x = &l_n_minus_1_of_x * &psw_of_x;
    let p4_of_x = &l_n_minus_1_of_x * &(&b_of_x - &one);
    let p_mrg_of_x = merge_polys(&[&p1_of_x, &p2_of_x, &p3_of_x, &p4_of_x], &χ_q);

    // Z(X) = X^n - 1 is sparse, so this division takes linear time
    let (q_mrg_of_x, remainder) = p_mrg_of_x.divide_by_vanishing_poly(domain).ok_or(
        HinTSError::CryptographyCatastrophe(
            format!("Unable to divide by the vanishing polynomial for n = {}", n)
        )
    )?;
    let exact = remainder.coeffs.iter().all(|c| *c == F::from(0));
    let q_mrg_of_tau_com = KZG::commit_g1(crs, &q_mrg_of_x)?;

    // Round 2: r binds [Q_mrg(τ)]_1, so the merged quotient cannot be chosen once r is known
    transcript.absorb(&q_mrg_of_tau_com)?;
    let r: F = transcript.challenge(DST_EVALUATION_POINT);
    let r_div_ω: F = r / ω;

    let parsum_of_r = psw_of_x.evaluate(&r);
    let parsum_of_r_div_ω = psw_of_x.evaluate(&r_div_ω);
    let w_of_r = w_of_x.evaluate(&r);
    let b_of_r = b_of_x.evaluate(&r);
    let q_mrg_of_r = q_mrg_of_x.evaluate(&r);

    // Round 3: χ_op is drawn once the claimed evaluations are fixed
    absorb_round_3(&mut transcript, &parsum_of_r, &parsum_of_r_div_ω, &w_of_r, &b_of_r, &q_mrg_of_r)?;
    let χ_op: F = transcript.challenge(DST_OPENING_BATCH);

    // a single opening at r, of Q = Q_mrg + χ_op·PS + χ_op^2·B + χ_op^3·W; the verifier
    // rebuilds [Q(τ)]_1 from the commitments, so it is not part of the signature
    let q_of_x = merge_polys(&[&q_mrg_of_x, &psw_of_x, &b_of_x, &w_of_x], &χ_op);
    let opening_proof_r = KZG::compute_opening_proof(crs, &q_of_x, &r)?;
    let opening_proof_r_div_ω = KZG::compute_opening_proof(crs, &psw_of_x, &r_div_ω)?;

    let π = ThresholdSignature {
        agg_pk: witness.agg_pk,
        agg_weight: witness.agg_weight,
        agg_sig: witness.agg_sig,

        b_of_tau_com,
        qx_of_tau_com: witness.qx_of_tau_com,
        qx_of_tau_mul_tau_com: witness.qx_of_tau_mul_tau_com,
        qz_of_tau_com: witness.qz_of_tau_com,
        parsum_of_tau_com,
        q_mrg_of_tau_com,

        opening_proof_r,
        opening_proof_r_div_ω,

        parsum_of_r,
        parsum_of_r_div_ω,
        w_of_r,
        b_of_r,
        q_mrg_of_r,
    };
    Ok((π, exact))
}

/// inclusive running sums of b_i · w_i over the slots
fn running_sums(weights: &[Weight], bitmap: &[F]) -> Vec<F> {
    let mut sum = F::from(0);
    weights
        .iter()
        .zip(bitmap.iter())
        .map(|(&w, &b)| {
            sum += b * w;
            sum
        })
        .collect()
}

/// interpolates evaluations over the multiplicative subgroup of their size
fn interpolate(evals: &Vec<F>) -> Result<DensePolynomial<F>, HinTSError> {
    utils::interpolate_poly_over_mult_subgroup(evals).ok_or(
        HinTSError::CryptographyCatastrophe(
            format!("Unable to construct Radix2EvaluationDomain for n = {}", evals.len())
        )
    )
}

/// p_0 + χ·p_1 + χ^2·p_2 + ..., by Horner's rule
fn merge_polys(polys: &[&DensePolynomial<F>], χ: &F) -> DensePolynomial<F> {
    polys
        .iter()
        .rev()
        .fold(DensePolynomial { coeffs: vec![] }, |acc, p| &utils::poly_eval_mult_c(&acc, χ) + *p)
}

/// a_0 + χ·a_1 + χ^2·a_2 + ..., by Horner's rule: `merge_polys` evaluated at a point
fn merge_scalars(values: &[F], χ: &F) -> F {
    values.iter().rev().fold(F::from(0), |acc, v| acc * χ + v)
}

/// [a_0] + χ·[a_1] + χ^2·[a_2] + ..., by Horner's rule: `merge_polys` in the exponent
fn merge_points(points: &[G1AffinePoint], χ: &F) -> G1AffinePoint {
    points
        .iter()
        .rev()
        .fold(G1AffinePoint::zero().into_group(), |acc, p| acc * χ + *p)
        .into_affine()
}

/// Round 1 of the transcript (T_1 in the whitepaper): the verification key, the aggregate
/// values, and every commitment fixed before the quotients are merged. [Q_mrg(τ)]_1 cannot
/// be absorbed here: χ_Q, which defines it, is this round's output.
fn absorb_round_1(
    transcript: &mut Transcript,
    vk: &VerificationKey,
    agg_pk: &G1AffinePoint,
    agg_weight: &F,
    b_of_tau_com: &G1AffinePoint,
    parsum_of_tau_com: &G1AffinePoint,
    qx_of_tau_com: &G1AffinePoint,
    qz_of_tau_com: &G1AffinePoint,
    qx_of_tau_mul_tau_com: &G1AffinePoint,
) -> Result<(), HinTSError> {
    transcript.absorb(vk)?;
    transcript.absorb(agg_pk)?;
    transcript.absorb(agg_weight)?;
    transcript.absorb(b_of_tau_com)?;
    transcript.absorb(parsum_of_tau_com)?;
    transcript.absorb(qx_of_tau_com)?;
    transcript.absorb(qz_of_tau_com)?;
    transcript.absorb(qx_of_tau_mul_tau_com)
}

/// Round 3 of the transcript (T_3): the claimed evaluations. χ_op is drawn only once they
/// are fixed, so they cannot be adapted to the coefficient that batches their openings.
fn absorb_round_3(
    transcript: &mut Transcript,
    parsum_of_r: &F,
    parsum_of_r_div_ω: &F,
    w_of_r: &F,
    b_of_r: &F,
    q_mrg_of_r: &F,
) -> Result<(), HinTSError> {
    transcript.absorb(parsum_of_r)?;
    transcript.absorb(parsum_of_r_div_ω)?;
    transcript.absorb(w_of_r)?;
    transcript.absorb(b_of_r)?;
    transcript.absorb(q_mrg_of_r)
}

/// re-derives the challenges (χ_Q, r, χ_op) from a signature, making the same transcript
/// calls in the same order as `prove`
fn derive_challenges(
    vk: &VerificationKey,
    π: &ThresholdSignature,
) -> Result<(F, F, F), HinTSError> {
    let mut transcript = Transcript::new();
    absorb_round_1(
        &mut transcript,
        vk,
        &π.agg_pk,
        &π.agg_weight,
        &π.b_of_tau_com,
        &π.parsum_of_tau_com,
        &π.qx_of_tau_com,
        &π.qz_of_tau_com,
        &π.qx_of_tau_mul_tau_com,
    )?;
    let χ_q: F = transcript.challenge(DST_QUOTIENT_MERGE);

    transcript.absorb(&π.q_mrg_of_tau_com)?;
    let r: F = transcript.challenge(DST_EVALUATION_POINT);

    absorb_round_3(
        &mut transcript,
        &π.parsum_of_r,
        &π.parsum_of_r_div_ω,
        &π.w_of_r,
        &π.b_of_r,
        &π.q_mrg_of_r,
    )?;
    let χ_op: F = transcript.challenge(DST_OPENING_BATCH);

    Ok((χ_q, r, χ_op))
}

/// BLS: e(aPK, H(m)) = e([1]_1, σ)
fn bls_check(
    msg: &[u8],
    vk: &VerificationKey,
    π: &ThresholdSignature,
) -> Result<bool, HinTSError> {
    let lhs = <Curve as Pairing>::pairing(&π.agg_pk, hash_to_g2(msg)?);
    let rhs = <Curve as Pairing>::pairing(vk.g_0, &π.agg_sig);
    Ok(lhs == rhs)
}

/// the merged relation at r: P_mrg(r) = Q_mrg(r) · Z(r), from the claimed evaluations
fn merged_relation_check(
    vk: &VerificationKey,
    π: &ThresholdSignature,
    ω: F,
    χ_q: F,
    r: F,
) -> bool {
    // this takes logarithmic computation, but concretely efficient
    let vanishing_of_r: F = r.pow([vk.n as u64]) - F::from(1);

    // compute L_{n-1}(r) using the relation L_i(x) = Z_V(x) / ( Z_V'(x) (x - ω^i) )
    // where Z_V'(x)^-1 = x / N for N = |V|.
    let ω_pow_n_minus_1 = ω.pow([(vk.n as u64) - 1]);
    let l_n_minus_1_of_r =
        (ω_pow_n_minus_1 / F::from(vk.n as u64)) * (vanishing_of_r / (r - ω_pow_n_minus_1));

    // P1..P4 at r, as defined in `prove`; W(r) is the verification key's own weight
    // polynomial, and the aggregate weight enters through the L_{n-1} term
    let p1 = π.parsum_of_r - π.parsum_of_r_div_ω
        - (π.w_of_r - π.agg_weight * l_n_minus_1_of_r) * π.b_of_r;
    let p2 = π.b_of_r * π.b_of_r - π.b_of_r;
    let p3 = l_n_minus_1_of_r * π.parsum_of_r;
    let p4 = l_n_minus_1_of_r * (π.b_of_r - F::from(1));

    merge_scalars(&[p1, p2, p3, p4], &χ_q) == π.q_mrg_of_r * vanishing_of_r
}

/// the single KZG opening at r of Q = Q_mrg + χ_op·PS + χ_op^2·B + χ_op^3·W; [Q(τ)]_1 is
/// rebuilt from the commitments by homomorphism, with the verification key's own [W(τ)]_1
fn opening_at_r_check(
    vk: &VerificationKey,
    π: &ThresholdSignature,
    r: F,
    χ_op: F,
) -> bool {
    let q_of_tau_com = merge_points(
        &[π.q_mrg_of_tau_com, π.parsum_of_tau_com, π.b_of_tau_com, vk.w_of_tau_com],
        &χ_op,
    );
    let q_of_r = merge_scalars(&[π.q_mrg_of_r, π.parsum_of_r, π.b_of_r, π.w_of_r], &χ_op);
    verify_opening(vk, &q_of_tau_com, &r, &q_of_r, &π.opening_proof_r)
}

/// the KZG opening of ParSum at r / ω
fn opening_at_r_div_ω_check(
    vk: &VerificationKey,
    π: &ThresholdSignature,
    r_div_ω: F,
) -> bool {
    verify_opening(vk, &π.parsum_of_tau_com, &r_div_ω, &π.parsum_of_r_div_ω, &π.opening_proof_r_div_ω)
}

/// the generalized sumcheck B(x) SK(x) = ask + Q_z(x) Z(x) + Q_x(x) x, in the exponent
fn sumcheck_check(
    vk: &VerificationKey,
    π: &ThresholdSignature,
    e_qx_tau: &PairingOutput<Curve>,
) -> bool {
    let lhs = <Curve as Pairing>::pairing(&π.b_of_tau_com, &vk.sk_of_tau_com);
    let x1 = <Curve as Pairing>::pairing(&π.qz_of_tau_com, &vk.z_of_tau_com);
    let x3 = <Curve as Pairing>::pairing(&π.agg_pk, &vk.h_0);
    lhs == x1 + *e_qx_tau + x3
}

/// the degree check e([Q_x(τ)]_1, [τ]_2) = e([Q_x(τ)·τ]_1, [1]_2)
fn degree_check(
    vk: &VerificationKey,
    π: &ThresholdSignature,
    e_qx_tau: &PairingOutput<Curve>,
) -> bool {
    *e_qx_tau == <Curve as Pairing>::pairing(&π.qx_of_tau_mul_tau_com, &vk.h_0)
}

// Generates a Schnorr proof of knowledge of the discrete log of the public key.
fn generate_proof_of_knowledge(
    x: &F,
    seed:[u8; RANDOM_SIZE]
) -> Result<ProofOfPossesion, HinTSError> {
    let g = G1AffinePoint::generator();
    let statement = (g * x).into_affine();

    let r = F::rand(&mut rand_chacha::ChaCha8Rng::from_seed(seed));
    let commitment = (g * r).into_affine();

    let challenge = proof_of_knowledge_random_oracle(g, statement, commitment)?;

    // compute response = r + challenge * x
    let response = r + challenge * x;

    Ok(ProofOfPossesion {
        commitment,
        challenge,
        response,
    })
}

// Verifies a Schnorr proof of knowledge of the discrete log of the public key.
fn verify_proof_of_knowledge(
    pok: &ProofOfPossesion,
    pubkey: &PublicKey
) -> Result<bool, HinTSError> {
    let g = G1AffinePoint::generator();
    let challenge = proof_of_knowledge_random_oracle(g, *pubkey, pok.commitment)?;
    let lhs = g * pok.response;
    let rhs = pok.commitment + (pubkey.clone() * pok.challenge);
    Ok(lhs.into_affine() == rhs && challenge == pok.challenge)
}

// Fiat-Shamir transform to derive challenge for proof of knowledge
fn proof_of_knowledge_random_oracle(
    g: G1AffinePoint,
    statement: G1AffinePoint,
    commitment: G1AffinePoint
) -> Result<F, HinTSError> {
    const POP_DST: &[u8] = b"HINTS_SIG_BLS12381:FIAT_SHAMIR_POP";
    let mut serialized_data = Vec::new();
    g.serialize_compressed(&mut serialized_data)
        .map_err(|e| HinTSError::EncodingError(e))?;
    statement
        .serialize_compressed(&mut serialized_data)
        .map_err(|e| HinTSError::EncodingError(e))?;
    commitment
        .serialize_compressed(&mut serialized_data)
        .map_err(|e| HinTSError::EncodingError(e))?;

    let hasher = <DefaultFieldHasher<Sha256> as HashToField<F>>::new(POP_DST);
    Ok(hasher.hash_to_field(&serialized_data, 1)[0])
}

fn verify_opening(
    vp: &VerificationKey,
    commitment: &G1AffinePoint,
    point: &F,
    evaluation: &F,
    opening_proof: &G1AffinePoint,
) -> bool {
    let eval_com: G1AffinePoint = vp.g_0.clone().mul(evaluation).into();
    let point_com: G2AffinePoint = vp.h_0.clone().mul(point).into();

    let lhs = <Curve as Pairing>::pairing(commitment.clone() - eval_com, vp.h_0);
    let rhs = <Curve as Pairing>::pairing(opening_proof.clone(), vp.h_1 - point_com);

    lhs == rhs
}

fn preprocess_qz_contributions(
    q1_contributions: &Vec<Vec<G1AffinePoint>>
) -> Vec<G1AffinePoint> {
    let n = q1_contributions.len();
    let mut q1_coms = vec![];

    for i in 0..n {
        // extract party i's hints, from which we extract the term for i.
        let mut party_i_q1_com = q1_contributions[i][i].clone();
        for j in 0..n {
            if i != j {
                // extract party j's hints, from which we extract cross-term for party i
                let party_j_contribution = q1_contributions[j][i].clone();
                party_i_q1_com = party_i_q1_com.add(party_j_contribution).into();
            }
        }
        // the aggregation key contains a single term that
        // is a product of all cross-terms and the ith term
        q1_coms.push(party_i_q1_com);
    }
    q1_coms
}

/// computes the inner product between a vector of group elements and bitvector;
/// the sum runs in projective coordinates and is normalized once, at the end
fn inner_product<T: AffineRepr>(
    elements: &Vec<T>,
    bitmap: &Vec<F>
) -> T {
    elements
        .iter()
        .zip(bitmap.iter())
        .filter(|(_, &bit)| bit == F::from(1))
        .map(|(elem, _)| elem)
        .sum::<T::Group>()
        .into_affine()
}

/// adds up all the group elements in a collection, in projective coordinates
fn add<T: AffineRepr>(elements: impl IntoIterator<Item = T>) -> T {
    elements.into_iter().sum::<T::Group>().into_affine()
}

/// hashes a byte array to an elliptic curve group element
pub fn hash_to_g2(
    msg: impl AsRef<[u8]>
) -> Result<G2AffinePoint, HinTSError> {
    const DST_G2: &str = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    let g2_mapper = MapToCurveBasedHasher::<
        G2ProjectivePoint,
        DefaultFieldHasher<Sha256, 128>,
        WBMap<G2Config>,
    >::new(DST_G2.as_bytes())?;
    g2_mapper.hash(msg.as_ref()).map_err(|e| HinTSError::HashingError(e))
}

pub fn serialize<T: CanonicalSerialize>(
    t: &T
) -> Result<Vec<u8>, HinTSError> {
    let mut buf = Vec::new();
    // unwrap() should be safe because we serialize into a variable-size vector.
    // However, it might fail if the `t` is invalid somehow, although this
    // should only occur if there is an error in the caller or this library.
    t.serialize_uncompressed(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::PowersOfTauProtocol;
    use rand::Rng;

    /// An UNSAFE private helper method to use in Rust unit tests in this inner `tests` module ONLY.
    /// This method assumes that the deserialization succeeds, which the tests must guarantee.
    /// DO NOT use this method in production code because it will cause a panic and a JVM crash
    /// if the input buffer cannot be deserialized properly.
    fn deserialize<T: CanonicalDeserialize>(buf: &[u8]) -> T {
        T::deserialize_uncompressed(buf).unwrap()
    }

    #[test]
    fn test_serialization() {
        let universe_n = 32;
        let num_signers = universe_n - 1;
        let msg = b"helloworld";

        let (crs, ak, vk, sks, epks) = sample_universe(universe_n);
        let sigs = sample_signing(num_signers, msg, &sks);
        let π = HinTS::aggregate(&crs, &ak, &vk, &sigs).unwrap();

        // test (de)-serialization
        let serialized_vk = serialize(&vk).unwrap();
        let deserialized_vk = deserialize::<VerificationKey>(&serialized_vk);

        let serialized_ak = serialize(&ak).unwrap();
        let deserialized_ak = deserialize::<AggregationKey>(&serialized_ak);

        let serialized_π = serialize(&π).unwrap();
        let deserialized_π = deserialize::<ThresholdSignature>(&serialized_π);

        let serialized_sk = serialize(&sks[0]).unwrap();
        let deserialized_sk = deserialize::<SecretKey>(&serialized_sk);

        let serialized_pk = serialize(&epks[0].pk_i).unwrap();
        let deserialized_pk = deserialize::<PublicKey>(&serialized_pk);

        let serialized_epk = serialize(&epks[0]).unwrap();
        let deserialized_epk = deserialize::<ExtendedPublicKey>(&serialized_epk);

        let serialized_crs = serialize(&crs).unwrap();
        let deserialized_crs = deserialize::<CRS>(&serialized_crs);

        assert_eq!(vk, deserialized_vk);
        assert_eq!(ak, deserialized_ak);
        assert_eq!(π, deserialized_π);
        assert_eq!(sks[0], deserialized_sk);
        assert_eq!(epks[0].pk_i, deserialized_pk);
        assert_eq!(epks[0], deserialized_epk);
        assert_eq!(crs, deserialized_crs);

        // print out sizes for our information
        println!("vk size: {}", serialized_vk.len());
        println!("ak size: {}", serialized_ak.len());
        println!("π size: {}", serialized_π.len());
        println!("sk size: {}", serialized_sk.len());
        println!("pk size: {}", serialized_pk.len());
        println!("epk size: {}", serialized_epk.len());
        println!("crs size: {}", serialized_crs.len());
    }

    #[test]
    fn it_works() {
        let universe_n = 32;
        let num_signers = universe_n - 1;
        let msg = b"hello";

        let (crs, ak, vk, sks, _) = sample_universe(universe_n);
        let sigs = sample_signing(num_signers, msg, &sks);

        for (i, sig) in sigs.iter() {
            assert!(HinTS::partial_verify(msg, &ak, *i, sig).unwrap());
        }

        assert!(
            HinTS::partial_verify_batch(
                msg,
                &ak,
                sigs.keys().cloned().collect::<Vec<usize>>(),
                sigs.values().cloned().collect::<Vec<PartialSignature>>()
            ).unwrap()
        );

        let π = HinTS::aggregate(&crs, &ak, &vk, &sigs).unwrap();

        let threshold = (F::from(1), F::from(3)); // 1/3
        assert!(HinTS::verify(msg, &vk, &π, threshold).unwrap());

        // attack the proof
        let mut π_attack = π.clone();
        π_attack.agg_weight = F::from(1000000000); // some arbitrary weight
        assert!(!HinTS::verify(msg, &vk, &π_attack, threshold).unwrap());

        // try a really high threshold of 99%
        assert!(!HinTS::verify(msg, &vk, &π_attack, (F::from(99), F::from(100))).unwrap());
    }

    fn sample_signing(
        num_signers: usize,
        msg: &[u8],
        sks: &Vec<SecretKey>,
    ) -> HashMap<usize, PartialSignature> {
        //samples n-1 random bits
        let bitmap = sample_bitmap(num_signers, 0.75);

        // for all the active parties, sample partial signatures
        // filter our bitmap indices that are 1
        let mut sigs = HashMap::new();
        bitmap.iter().enumerate().for_each(|(i, &bit)| {
            if bit == F::from(1) {
                sigs.insert(i, HinTS::sign(msg, &sks[i]).unwrap());
            }
        });

        sigs
    }

    fn sample_universe(
        n: usize,
    ) -> (
        CRS,
        AggregationKey,
        VerificationKey,
        Vec<SecretKey>,
        Vec<ExtendedPublicKey>,
    ) {
        let num_signers = n - 1;

        // -------------- sample one-time SRS ---------------
        let init_crs = PowersOfTauProtocol::init(n);
        // WARN: supply a random seed, not a fixed one as shown here.
        let (crs, proof) = PowersOfTauProtocol::contribute(&init_crs, [86u8; 32]).unwrap();
        assert!(PowersOfTauProtocol::verify_contribution(
            &init_crs, &crs, &proof
        ));

        // -------------- sample universe specific values ---------------
        //sample random keys
        // WARN: supply a random seed, not a fixed one as shown here.
        let sks: Vec<SecretKey> = (0..num_signers)
            .map(|_| HinTS::keygen([42u8; 32]).unwrap())
            .collect();

        let epks = (0..num_signers)
            .map(|i| HinTS::hint_gen(&crs, n, i, &sks[i]).unwrap())
            .collect::<Vec<ExtendedPublicKey>>();

        //sample random weights for each party
        let weights = sample_weights(num_signers);

        // -------------- perform universe setup ---------------
        let signers_info: HashMap<usize, (Weight, ExtendedPublicKey)> = (0..num_signers)
            .map(|i| (i, (weights[i], epks[i].clone())))
            .collect();

        //run universe setup
        let (vk, ak) = HinTS::preprocess(n, &crs, &signers_info).unwrap();

        (crs, ak, vk, sks, epks)
    }

    fn sample_weights(n: usize) -> Vec<F> {
        let rng = &mut ark_std::test_rng();
        (0..n)
            .map(|_| F::from(rng.gen_range(1..10)) + F::from(10))
            .collect()
    }

    /// n is the size of the bitmap, and probability is for true or 1.
    fn sample_bitmap(n: usize, probability: f64) -> Vec<F> {
        let rng = &mut ark_std::test_rng();
        let mut bitmap = vec![];
        for _i in 0..n {
            //let r = u64::rand(&mut rng);
            let bit = rng.gen_bool(probability);
            bitmap.push(F::from(bit));
        }
        bitmap
    }

    /// Deserialization must size a collection from what it actually reads, not from the
    /// declared length prefix, which is untrusted and unbounded. This pins the behaviour
    /// rather than a version: the pinned revision does not pre-size, a released one does,
    /// so a dependency change could alter it with no change here. Don't relax this test.
    #[test]
    fn test_vec_deserialization_does_not_preallocate() {
        let huge_length_prefix = (1u64 << 40).to_le_bytes();
        assert!(Vec::<F>::deserialize_uncompressed(huge_length_prefix.as_slice()).is_err());
    }

    /// crs_supports now requires the G2 tower to cover n as well, which nothing checked before.
    /// That is a widening, so pin that it accepts what every CRS constructor produces rather
    /// than relying on the towers being equal length by inspection.
    #[test]
    fn test_crs_supports_accepts_every_constructor() {
        for degree in [4usize, 8, 16, 32] {
            let init = PowersOfTauProtocol::init(degree);
            assert!(crs_supports(&init, degree), "init({})", degree);
            assert!(!crs_supports(&init, degree + 1), "init({}) must not claim {}", degree, degree + 1);

            let (contributed, _proof) = PowersOfTauProtocol::contribute(&init, [7u8; 32]).unwrap();
            assert!(crs_supports(&contributed, degree), "contribute at {}", degree);

            let pruned = PowersOfTauProtocol::prune_crs(&contributed, degree - 1).unwrap();
            assert!(crs_supports(&pruned, degree - 1), "prune to {}", degree - 1);
            assert!(!crs_supports(&pruned, degree), "pruned CRS must not claim {}", degree);
        }
    }

    /// The check at the end of preprocess fires on our own output, so getting it wrong would be
    /// a self-inflicted stall rather than a rejected attack: the node would log and skip voting.
    /// Pin it across sizes and signer densities instead of trusting that every vector is built
    /// as vec![_; n]. Sparsity matters because absent signers take the zero-key branch.
    #[test]
    fn test_preprocess_output_is_well_formed_across_sizes() {
        for universe_n in [4usize, 8, 16, 32] {
            let (crs, _ak, _vk, _sks, epks) = sample_universe(universe_n);
            let weights = sample_weights(universe_n);

            for signers in [universe_n - 1, 0, universe_n / 2] {
                let mut signer_info = HashMap::new();
                for i in 0..signers {
                    signer_info.insert(i, (weights[i], epks[i].clone()));
                }

                let (_vk, ak) = HinTS::preprocess(universe_n, &crs, &signer_info)
                    .unwrap_or_else(|e| panic!("n = {}, signers = {}: {:?}", universe_n, signers, e));

                assert_eq!(ak.n, universe_n);
                assert!(
                    aggregation_key_is_well_formed(&ak),
                    "n = {}, signers = {}: lengths {}, {}, {}, {}, {}",
                    universe_n, signers,
                    ak.weights.len(), ak.pks.len(), ak.qz_terms.len(),
                    ak.qx_terms.len(), ak.qx_mul_tau_terms.len()
                );
            }
        }
    }

    /// The signer count check only bounds how many entries there are, not which indices they
    /// use, so a caller could place a party on the index the scheme reserves for itself. aggregate
    /// overwrites that slot, so the keys build cleanly and then verify nothing.
    #[test]
    fn test_preprocess_rejects_reserved_party_index() {
        let n = 8usize;

        let (crs, _ak, _vk, sks, epks) = sample_universe(n);
        let weights = sample_weights(n);

        // hint_gen only rejects i >= n, so a hint for the reserved index verifies like any other.
        // Without an explicit bound this is what walks past the signer count check.
        let reserved_epk = HinTS::hint_gen(&crs, n, n - 1, &sks[0]).unwrap();

        // sanity: the same single-signer shape on a normal index is accepted
        let mut ok = HashMap::new();
        ok.insert(0usize, (weights[0], epks[0].clone()));
        assert!(HinTS::preprocess(n, &crs, &ok).is_ok());

        let mut bad = HashMap::new();
        bad.insert(n - 1, (weights[0], reserved_epk));
        assert!(HinTS::preprocess(n, &crs, &bad).is_err());
    }

    /// An empty batch used to report success: add() gives the identity in both groups, so the
    /// pairing check collapsed to 1_GT == 1_GT. The Java bridge already rejects an empty party
    /// list, so this only aligns the Rust API with the policy in front of it.
    #[test]
    fn test_rejects_empty_batch() {
        let universe_n = 32;
        let msg = b"helloworld";

        let (_crs, ak, _vk, sks, _epks) = sample_universe(universe_n);
        let sig = HinTS::sign(msg, &sks[0]).unwrap();

        // sanity: a real single-signer batch still verifies
        assert!(HinTS::partial_verify_batch(msg, &ak, [0usize], [sig]).unwrap());

        let no_ids: [usize; 0] = [];
        let no_sigs: [PartialSignature; 0] = [];
        assert!(HinTS::partial_verify_batch(msg, &ak, no_ids, no_sigs).is_err());
    }

    /// A key whose n disagrees with its vectors must be rejected by every consumer, rather
    /// than indexing past the end of pks / weights.
    #[test]
    fn test_rejects_aggregation_key_with_short_vectors() {
        let universe_n = 32;
        let msg = b"helloworld";

        let (crs, ak, vk, sks, _epks) = sample_universe(universe_n);
        let sigs = sample_signing(universe_n - 1, msg, &sks);
        let sig = HinTS::sign(msg, &sks[0]).unwrap();

        // sanity: the honest key is accepted
        assert!(HinTS::partial_verify(msg, &ak, 0, &sig).unwrap());

        let mut short = ak.clone();
        short.pks.pop();

        assert!(HinTS::partial_verify(msg, &short, 0, &sig).is_err());
        assert!(HinTS::partial_verify_batch(msg, &short, [0usize], [sig]).is_err());
        assert!(HinTS::aggregate(&crs, &short, &vk, &sigs).is_err());
    }

    /// An empty g tower used to satisfy the size check by wrapping `len() - 1`, and
    /// verify_hint then indexed powers_of_g[0] directly. The h tower is left intact so the
    /// commitments along the way still succeed and execution reaches that index.
    #[test]
    fn test_rejects_crs_with_empty_g_tower() {
        let universe_n = 32;

        let (crs, _ak, _vk, _sks, epks) = sample_universe(universe_n);

        let no_g = CRS { powers_of_g: vec![], powers_of_h: crs.powers_of_h.clone() };
        assert!(HinTS::verify_hint(&no_g, universe_n, 0, &epks[0]).is_err());

        // and the h tower is checked too, which it previously never was
        let no_h = CRS { powers_of_g: crs.powers_of_g.clone(), powers_of_h: vec![] };
        assert!(HinTS::verify_hint(&no_h, universe_n, 0, &epks[0]).is_err());
    }

    /// verify now rejects a degenerate n up front. Note this only pins the early rejection:
    /// with a proof built for the honest key the openings check already returns false before
    /// execution reaches the division by vk.n, so it is not a regression test for that panic.
    #[test]
    fn test_verify_rejects_degenerate_n() {
        let universe_n = 32;
        let msg = b"helloworld";

        let (crs, ak, vk, sks, _epks) = sample_universe(universe_n);
        let sigs = sample_signing(universe_n - 1, msg, &sks);
        let π = HinTS::aggregate(&crs, &ak, &vk, &sigs).unwrap();

        // sanity: the honest key verifies
        assert!(HinTS::verify(msg, &vk, &π, (F::from(1), F::from(2))).unwrap());

        for bad_n in [0usize, 1, 3] {
            let mut bad_vk = vk.clone();
            bad_vk.n = bad_n;
            assert!(!HinTS::verify(msg, &bad_vk, &π, (F::from(1), F::from(2))).unwrap());
        }
    }

    /// inner_product and add now sum in projective coordinates; pin them against the plain
    /// affine fold they replaced, including the empty sum
    #[test]
    fn test_group_sums_match_affine_fold() {
        let (_crs, ak, _vk, _sks, _epks) = sample_universe(8);
        let bitmap: Vec<F> = [1u64, 0, 1, 1, 0, 0, 1, 1].iter().map(|&b| F::from(b)).collect();

        let expected = ak
            .qz_terms
            .iter()
            .zip(bitmap.iter())
            .filter(|(_, &bit)| bit == F::from(1))
            .fold(G1AffinePoint::zero(), |acc, (p, _)| (acc + p).into_affine());
        assert_eq!(inner_product(&ak.qz_terms, &bitmap), expected);

        // qz terms sum to zero by construction; pks repeat one key: a non-zero sum that exercises doubling
        assert_eq!(add(ak.pks.clone()), ak.pks.iter().fold(G1AffinePoint::zero(), |acc, p| (acc + p).into_affine()));
        assert_eq!(add(Vec::<G2AffinePoint>::new()), G2AffinePoint::zero());
    }

    /// The aggregate signature is 9 G1 points, 1 G2 point and 6 scalars. JNI moves it
    /// uncompressed (96, 192 and 32 bytes each), and HintsLibraryBridge and TSS hard-code
    /// that length, so pin it exactly.
    #[test]
    fn test_signature_size() {
        let msg = b"size";
        let (crs, ak, vk, sks, _) = sample_universe(8);
        let sigs: HashMap<usize, PartialSignature> =
            (0..7).map(|i| (i, HinTS::sign(msg, &sks[i]).unwrap())).collect();
        let π = HinTS::aggregate(&crs, &ak, &vk, &sigs).unwrap();
        assert_eq!(serialize(&π).unwrap().len(), 9 * 96 + 192 + 6 * 32);
        assert_eq!(serialize(&π).unwrap().len(), 1248);
    }

    /// The outcome of each of verify's checks, all of them evaluated, so tests can assert
    /// which check rejects a signature.
    #[derive(Debug, PartialEq)]
    struct CheckOutcomes {
        bls: bool,
        merged_relation: bool,
        opening_at_r: bool,
        opening_at_r_div_ω: bool,
        sumcheck: bool,
        degree: bool,
    }

    impl CheckOutcomes {
        fn all_pass() -> Self {
            CheckOutcomes {
                bls: true,
                merged_relation: true,
                opening_at_r: true,
                opening_at_r_div_ω: true,
                sumcheck: true,
                degree: true,
            }
        }
    }

    /// runs every check verify makes after its guards, without stopping at the first failure
    fn run_all_checks(msg: &[u8], vk: &VerificationKey, π: &ThresholdSignature) -> CheckOutcomes {
        let ω: F = utils::nth_root_of_unity(vk.n).unwrap();
        let (χ_q, r, χ_op) = derive_challenges(vk, π).unwrap();
        let e_qx_tau = <Curve as Pairing>::pairing(&π.qx_of_tau_com, &vk.h_1);
        CheckOutcomes {
            bls: bls_check(msg, vk, π).unwrap(),
            merged_relation: merged_relation_check(vk, π, ω, χ_q, r),
            opening_at_r: opening_at_r_check(vk, π, r, χ_op),
            opening_at_r_div_ω: opening_at_r_div_ω_check(vk, π, r / ω),
            sumcheck: sumcheck_check(vk, π, &e_qx_tau),
            degree: degree_check(vk, π, &e_qx_tau),
        }
    }

    /// partial signatures from every party in `parties`
    fn sign_all(
        msg: &[u8],
        sks: &Vec<SecretKey>,
        parties: impl IntoIterator<Item = usize>,
    ) -> HashMap<usize, PartialSignature> {
        parties
            .into_iter()
            .map(|i| (i, HinTS::sign(msg, &sks[i]).unwrap()))
            .collect()
    }

    /// Aggregation and verification agree across domain sizes, from the smallest (a single
    /// real party) up, and across participation: everyone, one signer, every other party.
    #[test]
    fn test_round_trip_across_sizes_and_participation() {
        let msg = b"round trip";
        for n in [2usize, 4, 8, 32] {
            let (crs, ak, vk, sks, _) = sample_universe(n);
            let participations = [
                ("everyone", sign_all(msg, &sks, 0..n - 1)),
                ("a single signer", sign_all(msg, &sks, [0])),
                ("every other party", sign_all(msg, &sks, (0..n - 1).step_by(2))),
            ];
            for (label, sigs) in participations.iter() {
                let π = HinTS::aggregate(&crs, &ak, &vk, sigs).unwrap();
                // any positive weight clears (0, 1), so this pins the proof, not the threshold
                assert!(
                    HinTS::verify(msg, &vk, &π, (F::from(0), F::from(1))).unwrap(),
                    "n = {}, {}", n, label
                );
                assert_eq!(run_all_checks(msg, &vk, &π), CheckOutcomes::all_pass(), "n = {}, {}", n, label);
                // every party shares one key, so BLS pins how many parties signed but not which;
                // the weights differ per party, so the claimed weight pins which were credited
                assert_eq!(
                    π.agg_weight,
                    sigs.keys().fold(F::from(0), |acc, &i| acc + ak.weights[i]),
                    "n = {}, {}", n, label
                );
            }
        }
    }
}
