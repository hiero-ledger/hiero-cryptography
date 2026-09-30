//! Native Schnorr signatures, key proofs, and three-round multisignatures.

use crate::{
  constants::{DST_NONCE_COMMITMENT, DST_POK, DS_CHALLENGE, ENTROPY_SIZE, NUM_CHALLENGE_BITS},
  error::WrapsError,
  poseidon::{poseidon_native, Constants},
  utils::{encode_point, le_bits_of},
};
use core::marker::PhantomData;
use ff::{Field, PrimeField, PrimeFieldBits};
use nova_snark::{gadgets::utils::field_switch, provider::traits::DlogGroup, traits::Engine};
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Reduces `x` to its low `NUM_CHALLENGE_BITS` bits, so that the result has the same
/// canonical representation in both fields of the curve cycle.
fn truncate_to_challenge<F: PrimeFieldBits>(x: &F) -> F {
  let mut acc = F::ZERO;
  let mut coeff = F::ONE;
  for bit in le_bits_of(x, NUM_CHALLENGE_BITS) {
    if bit {
      acc += coeff;
    }
    coeff = coeff.double();
  }
  acc
}

// =========================================================================
// Schnorr over `E::GE`, with Poseidon as the hash function.
// =========================================================================

// The Schnorr value types. Each is a plain projection of `E` rather than a newtype, so
// they carry intent without changing what the code does or what it costs; and each is
// written without an `E: Engine` bound, since bounds on a type alias are not enforced
// and would only draw a `type_alias_bounds` warning.

/// A Schnorr secret key: a scalar of the curve `E::GE`, sampled uniformly.
pub type SchnorrSecretKey<E> = <E as Engine>::Scalar;

/// A Schnorr public key: the curve point `sk·G`.
///
/// Distinct from a bare `E::GE` in intent — the nonce commitment `r` is also a group
/// element, but it is not a key.
pub type SchnorrPublicKey<E> = <E as Engine>::GE;

/// A circuit-compatible Schnorr signature challenge, truncated to `NUM_CHALLENGE_BITS` bits.
///
/// Embedded in `E::Base` and lifted exactly to `E::Scalar` for group arithmetic.
/// Signature challenges use Poseidon to match the circuit. Native key proofs instead
/// use the scalar-field [`SchnorrPoKChallenge`].
pub type SchnorrChallenge<E> = <E as Engine>::Base;

/// A native proof-of-knowledge challenge obtained by reducing SHA-256 into the scalar field.
///
/// Uses all 32 digest bytes, without truncation or conversion through the base field.
pub type SchnorrPoKChallenge<E> = <E as Engine>::Scalar;

/// A Schnorr response `s = k + sk·e`.
///
/// A scalar like the secret key, but not key material: it is published as half of the
/// signature, and the circuit only ever quantifies over it existentially.
pub type SchnorrResponse<E> = <E as Engine>::Scalar;

/// A Schnorr nonce `k`, the secret behind the commitment `r = k·G`.
///
/// As sensitive as the secret key: two signatures on different messages that share a
/// nonce give up `sk = (s - s') / (e - e')`.
pub(crate) type SchnorrNonce<E> = <E as Engine>::Scalar;

/// A Schnorr key pair over the curve `E::GE`.
///
/// The serialized form carries `sk`, so it is key material rather than something to
/// hand out; only `pk` is safe to publish.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub(crate) struct Keypair<E: Engine> {
  pub(crate) sk: SchnorrSecretKey<E>,
  pub(crate) pk: SchnorrPublicKey<E>,
}

/// A Schnorr signature: the challenge `e` and the response `s = k + sk·e`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Signature<E: Engine> {
  pub e: SchnorrChallenge<E>,
  pub s: SchnorrResponse<E>,
}

/// A proof that whoever published `pk` knows the matching secret.
///
/// The sigma protocol behind Schnorr, Fiat–Shamir'd: commit to `r·G`, take
/// `e = H(G, pk, r·G)`, answer `z = r + e·sk`. Verified as `z·G == commitment + e·pk`,
/// with the challenge recomputed so the proof cannot carry its own.
/// The native challenge uses domain-separated SHA-256; the circuit does not check it.
///
/// This is what makes summing public keys a safe way to aggregate: a rogue
/// `pk_n := x·G − Σ_{i<n} pk_i` has discrete log `x − Σ sk_i`, which its author does
/// not know, so no proof of knowledge exists for it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct SchnorrPoK<E: Engine> {
  pub commitment: SchnorrPublicKey<E>,
  pub challenge: SchnorrPoKChallenge<E>,
  pub response: SchnorrResponse<E>,
}

/// A public key together with its proof of knowledge.
pub type SchnorrAttestedPubKey<E> = (SchnorrPublicKey<E>, SchnorrPoK<E>);

/// Schnorr over `E::GE`: Poseidon for signatures, SHA-256 for native key proofs.
pub(crate) struct Schnorr<E: Engine> {
  _p: PhantomData<E>,
}

impl<E: Engine> Schnorr<E>
where
  E::GE: DlogGroup,
{
  /// The Schnorr challenge `e = H(pk, r, m)`, truncated to `NUM_CHALLENGE_BITS` bits.
  ///
  /// `msg` is a slice of field elements rather than one: a rotation message is the pair
  /// `[H(ab_next), H(hints_vk_next)]`. The sponge's IO pattern encodes the number of
  /// absorbed elements, so messages of different lengths cannot collide.
  fn challenge(
    pc: &Constants<E::Base>,
    pk: &SchnorrPublicKey<E>,
    r: &E::GE,
    msg: &[E::Base],
  ) -> SchnorrChallenge<E> {
    let pk = encode_point::<E>(pk);
    let r = encode_point::<E>(r);
    let elements = [&pk[..], &r[..], msg].concat();

    truncate_to_challenge(&poseidon_native(pc, DS_CHALLENGE, &elements))
  }

  /// Samples a secret key from `E::Scalar` and derives `pk = sk·G`.
  pub(crate) fn keygen(rng: &mut (impl RngCore + CryptoRng)) -> Keypair<E> {
    let sk = SchnorrSecretKey::<E>::random(rng);
    let pk = E::GE::gen() * sk;

    Keypair { sk, pk }
  }

  /// Signs `msg`: sample `k`, set `r = k·G`, `e = H(pk, r, msg)`, `s = k + sk·e`.
  pub(crate) fn sign(pc: &Constants<E::Base>, kp: &Keypair<E>, msg: &[E::Base]) -> Signature<E> {
    let k = SchnorrNonce::<E>::random(&mut OsRng);
    let r = E::GE::gen() * k;
    let e = Self::challenge(pc, &kp.pk, &r, msg);
    let s = k + kp.sk * field_switch::<E::Base, E::Scalar>(e);

    Signature { e, s }
  }

  /// Recovers `r = s·G - e·pk` and checks that it hashes back to `e`.
  pub(crate) fn verify(
    pc: &Constants<E::Base>,
    pk: &SchnorrPublicKey<E>,
    msg: &[E::Base],
    sig: &Signature<E>,
  ) -> bool {
    let e = field_switch::<E::Base, E::Scalar>(sig.e);
    let r = E::GE::gen() * sig.s - *pk * e;

    Self::challenge(pc, pk, &r, msg) == sig.e
  }

  /// Derives a PoK challenge by reducing a domain-separated SHA-256 digest into `E::Scalar`.
  ///
  /// Each point contributes the fixed-width canonical field representations of its
  /// affine coordinates and infinity flag, in that order. For Grumpkin these are
  /// three 32-byte little-endian values. All 32 digest bytes are interpreted as one
  /// big-endian integer and reduced modulo the scalar field's modulus. This direct
  /// reduction retains modulo bias; it is not a uniform-field sampling procedure.
  ///
  /// This v4 transcript replaces the previous PoK formats. Existing keys
  /// must be re-attested; their book commitments stay unchanged because PoKs are
  /// excluded from the address-book hash.
  pub(crate) fn pok_challenge(
    pk: &SchnorrPublicKey<E>,
    commitment: &E::GE,
  ) -> SchnorrPoKChallenge<E> {
    let mut hasher = Sha256::new();
    hasher.update(DST_POK);
    for point in [E::GE::gen(), *pk, *commitment] {
      for element in encode_point::<E>(&point) {
        hasher.update(element.to_repr().as_ref());
      }
    }

    // Horner evaluation in the scalar field computes the full big-endian digest
    // modulo its modulus, independently of the field's byte encoding.
    let radix = E::Scalar::from(256u64);
    hasher
      .finalize()
      .iter()
      .fold(E::Scalar::ZERO, |acc, &byte| {
        acc * radix + E::Scalar::from(u64::from(byte))
      })
  }

  /// Produces a proof of knowledge of `kp.sk`.
  ///
  /// The nonce uses its own randomness, separate from secret-key sampling.
  /// `WRAPS::keygen` supplies a deterministic stream from the expanded PoK seed.
  pub(crate) fn prove_knowledge(
    kp: &Keypair<E>,
    rng: &mut (impl RngCore + CryptoRng),
  ) -> SchnorrPoK<E> {
    let r = SchnorrNonce::<E>::random(rng);
    let commitment = E::GE::gen() * r;
    let challenge = Self::pok_challenge(&kp.pk, &commitment);
    let response = r + kp.sk * challenge;

    SchnorrPoK {
      commitment,
      challenge,
      response,
    }
  }

  /// Checks a proof of knowledge against the key it claims to speak for.
  pub(crate) fn verify_knowledge(pk: &SchnorrPublicKey<E>, pok: &SchnorrPoK<E>) -> bool {
    // Recomputing the challenge is what stops a proof carrying one of its own choosing.
    if Self::pok_challenge(pk, &pok.commitment) != pok.challenge {
      return false;
    }
    E::GE::gen() * pok.response == pok.commitment + *pk * pok.challenge
  }
}

// =========================================================================
// A three-round weighted Schnorr multisignature.
// =========================================================================
//
// The rounds are commit, reveal, respond:
//
//   1. every signer derives a nonce `k_i` from its session seed and broadcasts
//      `SHA256(k_i·G)` — a commitment to its nonce point, not the point itself;
//   2. every signer opens that commitment by broadcasting `r_i = k_i·G`;
//   3. every signer checks all the openings, derives the shared challenge
//      `e = Poseidon(Σ pk_j, Σ r_j, m)`, and answers with `s_i = k_i + sk_i·e`.
//
// The two hashes are different on purpose. The challenge has to be Poseidon: the circuit
// recomputes it, so it has to be cheap in constraints. The round-1 commitment never
// enters a circuit — it is opened and checked entirely between signers — so it uses
// SHA-256 instead, which is far faster natively and keeps the commitment's binding from
// resting on the same primitive as the challenge.
//
// Summing the responses gives `s = Σ k_i + e·Σ sk_i`, an ordinary single-signer
// Schnorr signature under the joint key `Σ pk_i`: it satisfies `s·G − e·(Σ pk_i) = Σ r_i`.
// So the aggregate is accepted by [`Schnorr::verify`] and by [`crate::circuit::RotationCircuit`] with no
// changes to either.
//
// Every sum here — the challenge derivation in round 3, the aggregation, the native
// verification, and the in-circuit aggregation — runs over the *signing subset* named by
// the bitvector, never over the whole address book. It has to: the verifier recomputes
// `e` from the joint key, so a challenge derived over one key set cannot be checked
// against another.
//
// Round 1 is what makes this safe to run concurrently. A two-round variant, where signers
// publish `r_i` directly, lets whoever speaks last choose its nonce after seeing the
// others; across enough parallel sessions that becomes a k-sum problem solvable with
// Wagner's algorithm. Binding each nonce before any is revealed removes that freedom.

/// A round-1 message: a SHA-256 commitment to the signer's nonce point.
///
/// Not a field element, and deliberately not Poseidon. This commitment is opened and
/// checked entirely off-circuit — no step ever proves anything about it — so it is free
/// to use a hash that is fast natively rather than one chosen to be cheap in constraints.
/// It also means a weakness in one of the two primitives does not carry across: the
/// commitment binding and the challenge derivation rest on different functions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigRound1 {
  /// SHA-256 commitment to the signer's nonce point.
  pub nonce_commitment: [u8; 32],
}

/// A round-2 message: the nonce point itself, opening the round-1 commitment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MultisigRound2<E: Engine> {
  /// The nonce point whose commitment was broadcast in round 1.
  pub nonce_point: E::GE,
}

/// A round-3 message: one signer's partial signature.
///
/// Shaped like a [`Signature`], but it is not one: `s` answers only for this signer's
/// share, so it verifies against `r_i` and `pk_i` rather than against the group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MultisigRound3<E: Engine> {
  /// This signer's response to the shared challenge.
  pub partial_signature: Signature<E>,
}

/// A broadcast message, carrying its round alongside the typed payload.
///
/// [`crate::wraps::WRAPS::signing_protocol`] encodes this envelope for transport and decodes it when
/// consuming earlier rounds. The tag prevents a payload from being used in the wrong
/// round. Supply the bytes in signing-subset order, regardless of arrival order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum RoundMessage<E: Engine> {
  /// A commitment to a nonce point.
  Round1(MultisigRound1),
  /// An opening of the round-1 commitment.
  Round2(MultisigRound2<E>),
  /// A partial signature over the shared challenge.
  Round3(MultisigRound3<E>),
}

/// The public half of the protocol: what any participant, or the aggregator, can compute
/// from the broadcast messages alone.
pub(crate) struct Multisig<E: Engine> {
  _p: PhantomData<E>,
}

impl<E: Engine> Multisig<E>
where
  E::GE: DlogGroup,
{
  /// Derives a protocol instance's nonce deterministically from its entropy.
  ///
  /// The rounds are stateless: a signer holds nothing between them, and each round
  /// re-derives `k` from the entropy it is handed. That is why the caller **must** pass
  /// the same value to rounds 1, 2 and 3 of one instance — round 1 commits to `k·G`,
  /// round 2 opens that commitment, and round 3 answers with `k + sk·e`, so all three
  /// have to land on the same `k` or the session simply fails to verify.
  ///
  /// The flip side is the caller's obligation: a **fresh** value per instance. Two
  /// instances sharing entropy repeat `k` under different challenges, and the pair of
  /// responses gives up `sk = (s - s') / (e - e')`. Nothing here can detect that — the
  /// function sees one seed at a time — so it is a contract, not a check.
  pub(crate) fn nonce(protocol_instance_entropy: [u8; ENTROPY_SIZE]) -> SchnorrNonce<E> {
    use rand_core::SeedableRng;
    SchnorrNonce::<E>::random(&mut rand_chacha::ChaCha20Rng::from_seed(
      protocol_instance_entropy,
    ))
  }

  /// The round-1 commitment to a nonce point.
  pub(crate) fn commit_nonce(r: &E::GE) -> MultisigRound1 {
    let mut hasher = Sha256::new();
    hasher.update(DST_NONCE_COMMITMENT);
    for element in encode_point::<E>(r) {
      hasher.update(element.to_repr().as_ref());
    }

    MultisigRound1 {
      nonce_commitment: hasher.finalize().into(),
    }
  }

  /// The joint public key `Σ pk_i` of a set of signers.
  pub(crate) fn aggregate_key(
    public_keys: &[SchnorrPublicKey<E>],
  ) -> Result<SchnorrPublicKey<E>, WrapsError> {
    public_keys
      .iter()
      .copied()
      .reduce(|acc, pk| acc + pk)
      .ok_or_else(|| WrapsError::invalid_input("a signing set must have at least one member"))
  }

  /// Round 1: publish a commitment to this instance's nonce.
  pub(crate) fn round1(protocol_instance_entropy: [u8; ENTROPY_SIZE]) -> MultisigRound1 {
    Self::commit_nonce(&(E::GE::gen() * Self::nonce(protocol_instance_entropy)))
  }

  /// Round 2: open the commitment by publishing the nonce point.
  ///
  /// The public protocol checks that every round-1 message, including this signer's
  /// commitment, is present before calling this helper. Round 3 checks all openings.
  pub(crate) fn round2(protocol_instance_entropy: [u8; ENTROPY_SIZE]) -> MultisigRound2<E> {
    MultisigRound2 {
      nonce_point: E::GE::gen() * Self::nonce(protocol_instance_entropy),
    }
  }

  /// Verifies every opening and derives the challenge the whole group answers.
  ///
  /// Every signer runs this in round 3, so a signer who lies in round 2 is caught by
  /// everyone rather than only by the aggregator.
  fn challenge(
    pc: &Constants<E::Base>,
    msg: &[E::Base],
    public_keys: &[SchnorrPublicKey<E>],
    round1: &[MultisigRound1],
    round2: &[MultisigRound2<E>],
  ) -> Result<SchnorrChallenge<E>, WrapsError> {
    let n = public_keys.len();
    if n == 0 {
      return Err(WrapsError::invalid_input(
        "a signing set must have at least one member",
      ));
    }
    if round1.len() != n || round2.len() != n {
      return Err(WrapsError::invalid_input(
        "round-1 and round-2 message counts must match the signing set",
      ));
    }

    for (i, r) in round2.iter().enumerate() {
      if Self::commit_nonce(&r.nonce_point) != round1[i] {
        return Err(WrapsError::invalid_input(format!(
          "signer {i}: the round-2 nonce does not open its round-1 commitment"
        )));
      }
    }

    let nonce_points = round2.iter().map(|m| m.nonce_point).collect::<Vec<_>>();
    let aggregate_r = Self::aggregate_key(&nonce_points)?;
    let aggregate_pk = Self::aggregate_key(public_keys)?;
    if aggregate_pk.to_coordinates().2 {
      return Err(WrapsError::invalid_input(
        "the signing set's aggregate public key must not be the identity",
      ));
    }

    Ok(Schnorr::<E>::challenge(
      pc,
      &aggregate_pk,
      &aggregate_r,
      msg,
    ))
  }

  /// Round 3: check every opening, then answer the group's shared challenge.
  pub(crate) fn round3(
    pc: &Constants<E::Base>,
    protocol_instance_entropy: [u8; ENTROPY_SIZE],
    msg: &[E::Base],
    sk: &SchnorrSecretKey<E>,
    public_keys: &[SchnorrPublicKey<E>],
    round1: &[MultisigRound1],
    round2: &[MultisigRound2<E>],
  ) -> Result<MultisigRound3<E>, WrapsError> {
    let e = Self::challenge(pc, msg, public_keys, round1, round2)?;
    let nonce = Self::nonce(protocol_instance_entropy);
    let pk = E::GE::gen() * *sk;
    let nonce_point = E::GE::gen() * nonce;
    // Address-book validation and sentinel filtering make participant keys unique.
    let signer = public_keys
      .iter()
      .position(|participant| *participant == pk)
      .ok_or_else(|| WrapsError::invalid_input("R3 signing key is not in the signing subset"))?;
    if round2[signer].nonce_point != nonce_point {
      return Err(WrapsError::invalid_input(
        "R3 session entropy does not match the signer's round-2 nonce",
      ));
    }
    let s = nonce + *sk * field_switch::<E::Base, E::Scalar>(e);

    Ok(MultisigRound3 {
      partial_signature: Signature { e, s },
    })
  }

  /// Combines the partial signatures into one ordinary Schnorr signature.
  ///
  /// Each partial is checked against the signer it came from, so a faulty share is
  /// attributed rather than just producing an aggregate that fails to verify.
  pub(crate) fn aggregate(
    pc: &Constants<E::Base>,
    msg: &[E::Base],
    public_keys: &[SchnorrPublicKey<E>],
    round1: &[MultisigRound1],
    round2: &[MultisigRound2<E>],
    round3: &[MultisigRound3<E>],
  ) -> Result<Signature<E>, WrapsError> {
    if round3.len() != public_keys.len() {
      return Err(WrapsError::invalid_input(
        "round-3 message count must match the signing set",
      ));
    }
    // Re-deriving the challenge also re-checks every round-1/round-2 opening.
    let e = Self::challenge(pc, msg, public_keys, round1, round2)?;
    let e_scalar = field_switch::<E::Base, E::Scalar>(e);

    for (i, partial) in round3.iter().enumerate() {
      let partial = &partial.partial_signature;
      if partial.e != e {
        return Err(WrapsError::invalid_input(format!(
          "signer {i}: partial signature answers a different challenge"
        )));
      }
      // The single-signer verification equation, restricted to this share.
      if E::GE::gen() * partial.s - public_keys[i] * e_scalar != round2[i].nonce_point {
        return Err(WrapsError::invalid_input(format!(
          "signer {i}: partial signature does not verify against its own nonce and key"
        )));
      }
    }

    let s = round3
      .iter()
      .fold(SchnorrResponse::<E>::ZERO, |acc, partial| {
        acc + partial.partial_signature.s
      });

    Ok(Signature { e, s })
  }
}
