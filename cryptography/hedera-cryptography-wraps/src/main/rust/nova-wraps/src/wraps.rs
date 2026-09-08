//! Address books, signing orchestration, and WRAPS proof construction and verification.

use crate::{
  circuit::RotationCircuit,
  constants::{DS_ADDRESS_BOOK, DS_HINTS_VK, ENTROPY_SIZE, HINTS_VK_CHUNK_SIZE, MAX_AB_SIZE},
  error::WrapsError,
  poseidon::{poseidon_native, shared_constants, Constants},
  schnorr::{
    Multisig, RoundMessage, Schnorr, SchnorrAttestedPubKey, SchnorrPoK, SchnorrPoKChallenge,
    SchnorrPublicKey, SchnorrResponse, SchnorrSecretKey, Signature,
  },
  utils::{
    decode, decode_compressed, encode, encode_compressed, encode_point, expand_seed, pad_bitvector,
    BitVector,
  },
};
use ff::Field;
use nova_snark::{
  nova::{self, CompressedSNARK, RecursiveSNARK},
  provider::{traits::DlogGroup, Bn256EngineKZG, GrumpkinEngine},
  traits::{snark::RelaxedR1CSSNARKTrait, Engine},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub type E1 = Bn256EngineKZG;
pub type E2 = GrumpkinEngine;
type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>; // non-preprocessing SNARK
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>; // non-preprocessing SNARK

/// The circuit field: Grumpkin's base field, which is BN254's scalar field.
pub type Base = <E2 as Engine>::Base;

/// A member's voting weight, encoded as an unsigned 64-bit integer.
pub type Weight = u64;

/// A member's identifier, opaque to this file but committed to by the book's hash.
pub type NodeId<E> = <E as Engine>::Base;

/// One address-book entry: its node id, attested public key, and weight.
pub type AddressBookEntry<E> = (NodeId<E>, SchnorrAttestedPubKey<E>, Weight);

/// A committee: up to [`MAX_AB_SIZE`] entries, in an order its hash commits to.
///
/// Variable length, so this is what a caller supplies. Everything that hashes or proves
/// one pads it internally first. Nonidentity public keys must be unique; sentinel
/// keys may repeat.
pub type AddressBook<E> = Vec<AddressBookEntry<E>>;

/// The Poseidon commitment to an address book, the first element of the IVC state.
pub type AddressBookHash<E> = <E as Engine>::Base;

/// The Poseidon hash of a hints verification key, the second element of the IVC state.
pub type HintsVKHash<E> = <E as Engine>::Base;

/// An aggregate signature together with the bitvector naming who produced it.
pub type SchnorrMultiSignature<E> = (BitVector, Signature<E>);

/// What a committee signs to authorise a rotation: the next book's hash and the hash of
/// the hints verification key that goes with it.
/// The elements are an [`AddressBookHash`] followed by a [`HintsVKHash`].
pub type RotationMessage<E> = [<E as Engine>::Base; 2];

/// The sentinel public key: the point at infinity.
///
/// Address books use it to hold a seat open for a member that does not exist yet. The
/// identity is the natural value for that — it is the additive unit, so an empty seat
/// contributes nothing to a joint key. A seat that contributes nothing to the key must
/// not contribute anything to a threshold either, and that is enforced where it counts:
/// [`subset_weight`] and [`RotationCircuit`] both treat an identity seat as carrying
/// zero weight, in the total as well as in the signing subset. A book may therefore put
/// any `u64` weight on an empty seat and it simply will not count, which is why
/// [`verify_address_book`] accepts one rather than refusing it. Once weight cannot be
/// claimed through it, the fact that anyone can forge a proof of knowledge for the
/// identity costs nothing.
pub(crate) fn sentinel_pubkey<E: Engine>() -> SchnorrPublicKey<E>
where
  E::GE: DlogGroup,
{
  E::GE::gen() * SchnorrSecretKey::<E>::ZERO
}

/// The attested sentinel key: the identity with a placeholder proof.
///
/// The proof is all zeros and is never checked. It exists only so that an empty seat has
/// the same shape as every other entry.
fn sentinel_attested_pubkey<E: Engine>() -> SchnorrAttestedPubKey<E>
where
  E::GE: DlogGroup,
{
  let pok = SchnorrPoK {
    commitment: sentinel_pubkey::<E>(),
    challenge: SchnorrPoKChallenge::<E>::ZERO,
    response: SchnorrResponse::<E>::ZERO,
  };

  (sentinel_pubkey::<E>(), pok)
}

/// The entry an address book is padded out with: an empty seat.
///
/// The sentinel key at zero weight, with a node id of `-1` that no real member would
/// carry. No key generation and no proof of knowledge, because there is no party here —
/// which is the whole point of the identity being the sentinel.
fn padding_entry<E: Engine>() -> AddressBookEntry<E>
where
  E::GE: DlogGroup,
{
  (
    -<E as Engine>::Base::ONE,
    sentinel_attested_pubkey::<E>(),
    0,
  )
}

/// Pads an address book out to exactly [`MAX_AB_SIZE`] entries.
///
/// The circuit has one shape, so every book it sees has one length. Padding is applied
/// on the way in — never stored, never signed as such — so a committee of 30 and the
/// same committee written out to 64 seats are the same book with the same hash.
pub(crate) fn pad_address_book<E: Engine>(ab: &AddressBook<E>) -> Result<AddressBook<E>, WrapsError>
where
  E::GE: DlogGroup,
{
  if ab.len() > MAX_AB_SIZE {
    return Err(WrapsError::invalid_input(format!(
      "address book has {} entries, more than the {MAX_AB_SIZE} the circuit can take",
      ab.len()
    )));
  }

  let mut padded = ab.clone();
  padded.resize(MAX_AB_SIZE, padding_entry::<E>());

  Ok(padded)
}

/// `H(ab)` — the commitment to a *padded* address book, and the IVC's running state.
///
/// Takes a book already run through [`pad_address_book`]; hashing a short one would
/// commit to something the circuit can never reproduce.
///
/// The preimage runs entry by entry, five elements each: node id, then the public key as
/// the circuit sees it — affine `x`, `y`, and the infinity flag — then weight. Building
/// it the same way in both places is what lets [`RotationCircuit`] recompute this hash
/// from its advice; [`encode_point`] is the single definition of how a key turns
/// into field elements, so the two cannot drift apart.
///
/// Order is part of the commitment, so two books differing only in the order of their
/// entries are different states even though they aggregate to the same joint key.
pub(crate) fn hash_address_book<E: Engine>(
  pc: &Constants<E::Base>,
  ab: &AddressBook<E>,
) -> AddressBookHash<E>
where
  E::GE: DlogGroup,
{
  debug_assert_eq!(
    ab.len(),
    MAX_AB_SIZE,
    "hash_address_book takes a padded book"
  );

  let elements = ab
    .iter()
    .flat_map(|(node_id, (pk, _pok), weight)| {
      let pk = encode_point::<E>(pk);
      [*node_id, pk[0], pk[1], pk[2], E::Base::from(*weight)]
    })
    .collect::<Vec<_>>();

  poseidon_native(pc, DS_ADDRESS_BOOK, &elements)
}

/// Checks key uniqueness, key proofs, and that the total effective weight fits in a `u64`.
///
/// Every weight is a `u64` by construction. Identity seats contribute zero to the
/// total, may repeat, and require no proof of possession. Every other key must be
/// unique and carry a valid proof of possession. Those proofs prevent rogue-key
/// aggregation attacks. Key uniqueness and possession are checked natively, not in the circuit.
/// The circuit independently enforces the per-seat and total weight bounds.
pub(crate) fn verify_address_book<E: Engine>(ab: &AddressBook<E>) -> bool
where
  E::GE: DlogGroup,
{
  if ab.len() > MAX_AB_SIZE {
    return false;
  }
  let mut seen_keys = Vec::with_capacity(ab.len());
  let mut total_weight = 0u64;
  ab.iter().all(|(_, (pk, pok), weight)| {
    // An entry whose key is the point at infinity is an empty seat, and there is
    // nothing about one to check. Its weight is stripped by the effective-weight rule
    // that `subset_weight` and `RotationCircuit` share, so it reaches no sum whatever
    // the entry says; and its proof of knowledge would be meaningless anyway, since for
    // `pk = O` the relation `z·G == commitment + e·pk` collapses to `z·G == commitment`,
    // which anyone satisfies by publishing `r·G` and answering `r`.
    //
    // Written against the infinity flag rather than against `sentinel_pubkey()`: the two
    // are the same value, which `sentinel_is_the_identity_so_the_weight_rule_covers_it`
    // pins down, but the property belongs to the identity itself rather than to whatever
    // this file happens to call the sentinel. Testing the flag keeps the rule correct
    // even if the sentinel is later changed to something else.
    if pk.to_coordinates().2 {
      return true;
    }
    if seen_keys.contains(pk) {
      return false;
    }
    seen_keys.push(*pk);

    let Some(total) = total_weight.checked_add(*weight) else {
      return false;
    };
    total_weight = total;
    Schnorr::<E>::verify_knowledge(pk, pok)
  })
}

/// Hashes a serialized hints verification key down to one field element.
///
/// Each 8-byte chunk is interpreted as a little-endian `u64`, with the final chunk
/// zero-padded. The length is absorbed first so that trailing zeros cannot be traded
/// against a shorter key. Native only — the circuit takes this hash as advice and
/// never recomputes it.
fn hash_hints_vk<E: Engine>(pc: &Constants<E::Base>, vk_bytes: &[u8]) -> HintsVKHash<E> {
  let mut elements = vec![E::Base::from(vk_bytes.len() as u64)];
  for chunk in vk_bytes.chunks(HINTS_VK_CHUNK_SIZE) {
    let mut buf = [0u8; HINTS_VK_CHUNK_SIZE];
    buf[..chunk.len()].copy_from_slice(chunk);
    elements.push(E::Base::from(u64::from_le_bytes(buf)));
  }

  poseidon_native(pc, DS_HINTS_VK, &elements)
}

/// The nonidentity public keys the bitvector names, in address-book order.
/// Sentinel seats do not participate in the signing rounds, even when selected.
pub(crate) fn signing_subset<E: Engine>(
  ab: &AddressBook<E>,
  bitvector: &BitVector,
) -> Vec<SchnorrPublicKey<E>>
where
  E::GE: DlogGroup,
{
  ab.iter()
    .zip(bitvector.iter())
    .filter_map(|((_, (pk, _pok), _), &signed)| (signed && !pk.to_coordinates().2).then_some(*pk))
    .collect()
}

/// `(weight carried by the signing subset, total weight of the book)`.
///
/// A seat keyed to the point at infinity carries no weight, in either sum. The identity
/// is the additive unit, so such a seat contributes nothing to a joint key and anyone
/// can "sign" for it; counting its weight would hand that weight to whoever claims the
/// seat. Dropping it from the total as well is what makes an empty seat equivalent to a
/// seat that does not exist — which is exactly what [`padding_entry`] is.
///
/// [`RotationCircuit`] applies the same rule, so the two agree on any book, including
/// one that never went through [`verify_address_book`]. Returns `None` for an oversized
/// book or a total weight above `u64::MAX`.
pub(crate) fn subset_weight<E: Engine>(
  ab: &AddressBook<E>,
  bitvector: &BitVector,
) -> Option<(Weight, Weight)>
where
  E::GE: DlogGroup,
{
  if ab.len() > MAX_AB_SIZE {
    return None;
  }
  ab.iter()
    .zip(bitvector.iter())
    .try_fold((0u64, 0u64), |(signing, total), (entry, &signed)| {
      let (_node_id, (pk, _pok), weight) = entry;
      let effective = if pk.to_coordinates().2 { 0 } else { *weight };

      let total = total.checked_add(effective)?;
      let signing = if signed {
        signing.checked_add(effective)?
      } else {
        signing
      };
      Some((signing, total))
    })
}

/// Whether the signing subset carries strictly more than half of the total weight.
///
/// Integer division gives `floor(total / 2)`, so this is exactly `2 * signing > total`
/// without doubling a value that could overflow. A subset cannot exceed the total.
pub(crate) fn meets_threshold(signing: &Weight, total: &Weight) -> bool {
  signing <= total && *signing > *total / 2
}

/// Which phase of the signing protocol to run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningProtocolPhase {
  R1,
  R2,
  R3,
  Aggregate,
}

/// Encoded [`RoundMessage`] bytes, passed unchanged between protocol phases.
pub type SigningProtocolMessage = Vec<u8>;

/// What a phase produced: a message to broadcast, or the finished multisignature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum SigningProtocolObject<E: Engine> {
  ProtocolMessage(SigningProtocolMessage),
  ProtocolOutput(SchnorrMultiSignature<E>),
}

type C = RotationCircuit<E2>;

/// Owned Nova folding parameters for the rotation circuit.
pub type PublicParams = nova::PublicParams<E1, E2, C>;

/// Owned Spartan prover key, separate from the folding parameters.
pub type ProverKey = nova::ProverKey<E1, E2, C, S1, S2>;

/// Owned Spartan verifier key, sufficient for compressed-proof verification.
pub type VerifierKey = nova::VerifierKey<E1, E2, C, S1, S2>;

/// A compressed proof together with the statement it speaks for.
///
/// Both proof forms carry the step count, initial state, and final state explicitly.
/// Verification checks that the SNARK authenticates this statement.
/// Encoded directly with bincode, without zlib, for fixed size at a fixed circuit shape.
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub(crate) struct CompressedWrapsProof {
  pub(crate) num_steps: usize,
  pub(crate) z0: Vec<Base>,
  pub(crate) zi: Vec<Base>,
  pub(crate) snark: CompressedSNARK<E1, E2, C, S1, S2>,
}

/// The running IVC proof together with the statement it speaks for.
///
/// The explicit metadata mirrors `CompressedWrapsProof`, even where `RecursiveSNARK`
/// also stores it internally. Verification checks that both representations agree.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub(crate) struct UncompressedWrapsProof {
  pub(crate) num_steps: usize,
  pub(crate) z0: Vec<Base>,
  pub(crate) zi: Vec<Base>,
  pub(crate) snark: RecursiveSNARK<E1, E2, C>,
}

/// Decode the fixed two-field statement, rejecting malformed or trailing bytes.
fn decode_rotation_message(bytes: &[u8]) -> Result<RotationMessage<E2>, WrapsError> {
  decode(bytes).map_err(|e| WrapsError::invalid_input(format!("invalid rotation message: {e}")))
}

/// Decode an expected round and retain the sender's position in the signing subset.
fn decode_round_messages<T>(
  messages: &[SigningProtocolMessage],
  round: &str,
  payload: impl Fn(RoundMessage<E2>) -> Option<T>,
) -> Result<Vec<T>, WrapsError> {
  messages
    .iter()
    .enumerate()
    .map(|(i, bytes)| {
      let message = decode::<RoundMessage<E2>>(bytes).map_err(|e| {
        WrapsError::invalid_input(format!("invalid {round} message from signer {i}: {e}"))
      })?;
      payload(message).ok_or_else(|| {
        WrapsError::invalid_input(format!(
          "{round} message from signer {i} has the wrong round tag"
        ))
      })
    })
    .collect()
}

/// Check each phase's required secret inputs and prior-round message counts.
fn validate_signing_phase(
  phase: SigningProtocolPhase,
  num_signers: usize,
  has_entropy: bool,
  has_signing_key: bool,
  round_counts: [usize; 3],
) -> Result<(), WrapsError> {
  use SigningProtocolPhase::{Aggregate, R1, R2, R3};
  let n = num_signers;
  let (needs_entropy, needs_signing_key, expected_counts) = match phase {
    R1 => (true, false, [0, 0, 0]),
    R2 => (true, false, [n, 0, 0]),
    R3 => (true, true, [n, n, 0]),
    Aggregate => (false, false, [n, n, n]),
  };
  if needs_entropy && !has_entropy {
    return Err(WrapsError::invalid_input(format!(
      "{phase:?} requires session entropy"
    )));
  }
  if needs_signing_key && !has_signing_key {
    return Err(WrapsError::invalid_input(
      "R3 requires the caller's signing key",
    ));
  }
  if round_counts != expected_counts {
    return Err(WrapsError::invalid_input(format!(
      "{phase:?} requires round-message counts {expected_counts:?} in signing-subset order"
    )));
  }
  Ok(())
}

/// Wrap the encoded round envelope in the public protocol result.
fn encode_protocol_message(
  message: RoundMessage<E2>,
) -> Result<SigningProtocolObject<E2>, WrapsError> {
  Ok(SigningProtocolObject::ProtocolMessage(encode(&message)?))
}

/// The library surface: key generation, the signing protocol, address-book hashing, and
/// proof construction and verification.
// Named to match the reference API rather than Rust naming conventions.
#[allow(clippy::upper_case_acronyms)]
pub struct WRAPS;

impl WRAPS {
  /// Derives a key pair and proof of knowledge deterministically from the provided entropy.
  ///
  /// SHA256(seed || 0x00) seeds secret-key sampling, and SHA256(seed || 0x01) seeds
  /// PoK nonce sampling. Each uses its own ChaCha20 stream, so repeating the input
  /// reproduces the full attested key without sharing randomness between the two roles.
  pub fn keygen(seed: [u8; ENTROPY_SIZE]) -> (SchnorrSecretKey<E2>, SchnorrAttestedPubKey<E2>) {
    use rand_core::SeedableRng;

    let [key_seed, pok_seed] = expand_seed(seed);
    let kp = Schnorr::<E2>::keygen(&mut rand_chacha::ChaCha20Rng::from_seed(key_seed));
    let pok =
      Schnorr::<E2>::prove_knowledge(&kp, &mut rand_chacha::ChaCha20Rng::from_seed(pok_seed));

    (kp.sk, (kp.pk, pok))
  }

  /// Returns the deterministic sentinel attested key.
  ///
  /// Its proof of knowledge is all zeros and is never checked: address-book validation
  /// skips sentinel proofs, because a seat nobody holds has no secret to prove.
  pub fn sentinel_keygen() -> SchnorrAttestedPubKey<E2> {
    sentinel_attested_pubkey::<E2>()
  }

  /// Executes a single phase of the three-round signing protocol.
  ///
  /// `protocol_instance_entropy` is per signer, per instance: the caller passes the same
  /// value through R1, R2 and R3 of one rotation — the rounds are stateless and each
  /// re-derives the signer's nonce from it — and a fresh one for the next rotation.
  /// Reusing a seed across rotations repeats the nonce; signatures under different
  /// challenges can then reveal the signer's secret key.
  ///
  /// Every phase works over the *signing subset* named by `bitvector`, never the whole
  /// address book — including the challenge derived in R3, which has to match the joint
  /// key that [`WRAPS::verify_signature`] and the circuit check against.
  ///
  /// # `message_to_sign` must come from [`WRAPS::compute_rotation_message`]
  ///
  /// R3 and Aggregate decode the two field elements from the supplied bytes and cannot
  /// look behind them. [`WRAPS::compute_rotation_message`] validates the book being
  /// endorsed before hashing it. That check establishes — for the whole rotation *after* this one —
  /// that every non-identity key is unique and came with a proof of possession. The
  /// circuit checks weight bounds but not key uniqueness or possession; see the
  /// crate-level "Trust boundary".
  ///
  /// So a signer must call [`WRAPS::compute_rotation_message`] in its own process, on
  /// the full `AddressBook` it means to endorse. Accepting a serialized [`RotationMessage`]
  /// from a proposer or another signer silently drops that check, and there is nothing
  /// downstream that can notice.
  ///
  /// R1 needs entropy and empty round-message lists; the book and message may be empty.
  /// R2 needs all R1 messages. R3 needs all R1/R2 messages and the caller's signing key.
  /// Aggregate needs all three rounds; entropy is optional and ignored. A signing key is required
  /// only in R3; it is optional and ignored in R1, R2, and Aggregate.
  /// Every phase validates the book and requires unused bitvector positions to be false.
  /// Selected sentinel seats require no round messages and are omitted from the participants.
  /// R2 onward also requires a nonempty subset of nonidentity keys. Quorum weight is
  /// checked by signature verification and proof construction, so below-threshold subsets may still sign.
  ///
  /// The round slices contain the bytes returned as `ProtocolMessage`, in signing-subset
  /// order. This method checks their round tags, decodes them, and validates the transcript.
  #[allow(clippy::too_many_arguments)]
  pub fn signing_protocol(
    phase: SigningProtocolPhase,
    protocol_instance_entropy: Option<[u8; ENTROPY_SIZE]>,
    message_to_sign: impl AsRef<[u8]>,
    signing_key: Option<&SchnorrSecretKey<E2>>,
    address_book: &AddressBook<E2>,
    bitvector: impl AsRef<[bool]>,
    round1_messages: &[SigningProtocolMessage],
    round2_messages: &[SigningProtocolMessage],
    round3_messages: &[SigningProtocolMessage],
  ) -> Result<SigningProtocolObject<E2>, WrapsError> {
    if !verify_address_book::<E2>(address_book) {
      return Err(WrapsError::invalid_input("invalid signing address book"));
    }
    let bitvector = pad_bitvector(bitvector.as_ref())?;
    if bitvector[address_book.len()..].iter().any(|&signed| signed) {
      return Err(WrapsError::invalid_input(
        "bitvector selects a seat outside the address book",
      ));
    }
    let participants = signing_subset(address_book, &bitvector);
    if phase != SigningProtocolPhase::R1 && participants.is_empty() {
      return Err(WrapsError::invalid_input(
        "a signing set must have at least one member",
      ));
    }
    validate_signing_phase(
      phase,
      participants.len(),
      protocol_instance_entropy.is_some(),
      signing_key.is_some(),
      [
        round1_messages.len(),
        round2_messages.len(),
        round3_messages.len(),
      ],
    )?;

    // Unused round lists are empty after phase validation, so they decode to empty vectors.
    let round1 = decode_round_messages(round1_messages, "round-1", |message| match message {
      RoundMessage::Round1(payload) => Some(payload),
      _ => None,
    })?;
    let round2 = decode_round_messages(round2_messages, "round-2", |message| match message {
      RoundMessage::Round2(payload) => Some(payload),
      _ => None,
    })?;
    let round3 = decode_round_messages(round3_messages, "round-3", |message| match message {
      RoundMessage::Round3(payload) => Some(payload),
      _ => None,
    })?;

    match phase {
      SigningProtocolPhase::R1 => {
        let seed = protocol_instance_entropy.expect("validated R1 entropy");
        encode_protocol_message(RoundMessage::Round1(Multisig::<E2>::round1(seed)))
      }
      SigningProtocolPhase::R2 => {
        let seed = protocol_instance_entropy.expect("validated R2 entropy");
        if !round1.contains(&Multisig::<E2>::round1(seed)) {
          return Err(WrapsError::invalid_input(
            "R2 is missing the caller's round-1 commitment",
          ));
        }
        encode_protocol_message(RoundMessage::Round2(Multisig::<E2>::round2(seed)))
      }
      SigningProtocolPhase::R3 => {
        let seed = protocol_instance_entropy.expect("validated R3 entropy");
        let sk = signing_key.expect("validated R3 signing key");
        let message = decode_rotation_message(message_to_sign.as_ref())?;
        let pc = shared_constants();
        let share =
          Multisig::<E2>::round3(&pc, seed, &message, sk, &participants, &round1, &round2)?;
        encode_protocol_message(RoundMessage::Round3(share))
      }
      SigningProtocolPhase::Aggregate => {
        let message = decode_rotation_message(message_to_sign.as_ref())?;
        let pc = shared_constants();
        let signature =
          Multisig::<E2>::aggregate(&pc, &message, &participants, &round1, &round2, &round3)?;
        Ok(SigningProtocolObject::ProtocolOutput((
          bitvector, signature,
        )))
      }
    }
  }

  /// Verifies an aggregate signature against the subset of the book that produced it.
  ///
  /// Returns `false`, rather than an error, whenever the committee is simply not
  /// entitled to the rotation: a malformed book, a subset below the weight threshold, or
  /// a signature that does not check out. Malformed rotation-message bytes are an error.
  pub fn verify_signature(
    address_book: &AddressBook<E2>,
    message: impl AsRef<[u8]>,
    multisignature: &SchnorrMultiSignature<E2>,
  ) -> Result<bool, WrapsError> {
    let message = decode_rotation_message(message.as_ref())?;
    let pc = shared_constants();
    let (bitvector, signature) = multisignature;

    if !verify_address_book::<E2>(address_book) {
      return Ok(false);
    }
    if bitvector[address_book.len()..].iter().any(|&signed| signed) {
      return Ok(false);
    }
    // Weighed and aggregated over the padded book, so this is arithmetic the circuit
    // performs on exactly the same 64 entries. Padding seats carry zero weight and a
    // false bit, so they change neither side of it.
    let address_book = pad_address_book::<E2>(address_book)?;

    let Some((signing_weight, total_weight)) = subset_weight::<E2>(&address_book, bitvector) else {
      return Ok(false);
    };
    if !meets_threshold(&signing_weight, &total_weight) {
      return Ok(false);
    }

    let participants = signing_subset(&address_book, bitvector);
    if participants.is_empty() {
      return Ok(false);
    }
    let joint = Multisig::<E2>::aggregate_key(&participants)?;
    if joint.to_coordinates().2 {
      return Ok(false);
    }

    Ok(Schnorr::<E2>::verify(&pc, &joint, &message, signature))
  }

  /// The Poseidon commitment to an address book, after checking the book is well formed.
  ///
  /// The book is padded to [`MAX_AB_SIZE`] first, so a committee's commitment does not
  /// depend on how many seats it happens to fill. Validation runs on what the caller
  /// supplied: padding entries are this file's own and need no vetting.
  pub fn compute_addressbook_hash(ab: &AddressBook<E2>) -> Result<AddressBookHash<E2>, WrapsError> {
    let pc = shared_constants();
    if !verify_address_book::<E2>(ab) {
      return Err(WrapsError::invalid_input(
        "address book is too large, has duplicate nonidentity keys or an invalid key proof, or its total effective weight exceeds u64::MAX",
      ));
    }

    Ok(hash_address_book::<E2>(&pc, &pad_address_book::<E2>(ab)?))
  }

  /// The Poseidon hash of a serialized hints verification key.
  pub fn compute_hints_vk_hash(hints_vk: impl AsRef<[u8]>) -> HintsVKHash<E2> {
    hash_hints_vk::<E2>(&shared_constants(), hints_vk.as_ref())
  }

  /// The encoded two-field message a committee signs to authorise a rotation.
  ///
  /// Pass these bytes directly to [`Self::signing_protocol`] and [`Self::verify_signature`].
  pub fn compute_rotation_message(
    ab_next: &AddressBook<E2>,
    hints_vk: impl AsRef<[u8]>,
  ) -> Result<Vec<u8>, WrapsError> {
    encode(&[
      Self::compute_addressbook_hash(ab_next)?,
      Self::compute_hints_vk_hash(hints_vk),
    ])
  }

  /// Builds the folding parameters used to derive prover and verifier keys.
  pub fn setup_public_params(ptau_dir: &std::path::Path) -> Result<PublicParams, WrapsError> {
    let pc = shared_constants();
    let circuit = C::dummy(&pc);

    PublicParams::setup_with_ptau_dir(&circuit, &*S1::ck_floor(), &*S2::ck_floor(), ptau_dir)
      .map_err(|e| WrapsError::cryptography(format!("public parameter setup failed: {e}")))
  }

  /// Derives an owned prover key from borrowed folding parameters.
  pub fn setup_prover(pp: &PublicParams) -> Result<ProverKey, WrapsError> {
    CompressedSNARK::<_, _, _, S1, S2>::setup(pp)
      .map(|(pk, _)| pk)
      .map_err(|e| WrapsError::cryptography(format!("compressing SNARK setup failed: {e}")))
  }

  /// Derives an owned verifier key from borrowed folding parameters.
  pub fn setup_verifier(pp: &PublicParams) -> Result<VerifierKey, WrapsError> {
    CompressedSNARK::<_, _, _, S1, S2>::setup(pp)
      .map(|(_, vk)| vk)
      .map_err(|e| WrapsError::cryptography(format!("compressing SNARK setup failed: {e}")))
  }

  /// Serializes the verifier key a standalone verifier needs.
  ///
  /// Only `vk` is emitted; `pp` stays with whoever ran the setup, since a verifier that
  /// has the compressed proof never touches the folding parameters.
  pub fn get_compressed_verification_key_bytes(vk: &VerifierKey) -> Result<Vec<u8>, WrapsError> {
    encode_compressed(vk)
  }

  /// Folds one rotation into the chain and compresses the result.
  ///
  /// With no `prev_proof` this is the genesis step: the previous book must hash to
  /// `ab_genesis_hash` and must equal the next one, so the chain starts by attesting
  /// itself. Otherwise the running proof is resumed from bytes and advanced by one step.
  ///
  /// Returns `(running proof, compressed proof)`. The first is fed back in as
  /// `prev_proof` next time; the second is what a verifier is handed. Both use
  /// [`encode`]; compression of the second proof is performed by Nova, without zlib.
  #[allow(clippy::too_many_arguments)]
  pub fn construct_wraps_proof(
    pp: &PublicParams,
    pk: &ProverKey,
    vk: &VerifierKey,
    ab_genesis_hash: &AddressBookHash<E2>,
    prev_ab: &AddressBook<E2>,
    next_ab: &AddressBook<E2>,
    prev_proof: Option<Vec<u8>>,
    hints_vk: impl AsRef<[u8]>,
    multi_signature: &SchnorrMultiSignature<E2>,
  ) -> Result<(Vec<u8>, Vec<u8>), WrapsError> {
    let pc = shared_constants();
    let (bitvector, signature) = multi_signature;

    if !verify_address_book::<E2>(prev_ab) {
      return Err(WrapsError::invalid_input("invalid previous address book"));
    }
    if !verify_address_book::<E2>(next_ab) {
      return Err(WrapsError::invalid_input("invalid next address book"));
    }
    if bitvector[prev_ab.len()..].iter().any(|&signed| signed) {
      return Err(WrapsError::invalid_input(
        "bitvector selects a seat outside the previous address book",
      ));
    }

    // Everything downstream — the hashes, the circuit — works on padded books.
    let prev_ab = pad_address_book::<E2>(prev_ab)?;
    let next_ab = pad_address_book::<E2>(next_ab)?;

    let prev_ab_hash = hash_address_book::<E2>(&pc, &prev_ab);
    let next_ab_hash = hash_address_book::<E2>(&pc, &next_ab);
    let hints_vk_hash: HintsVKHash<E2> = Self::compute_hints_vk_hash(hints_vk.as_ref());

    let is_genesis = prev_proof.is_none();
    if is_genesis {
      if *ab_genesis_hash != prev_ab_hash {
        return Err(WrapsError::invalid_input(
          "no previous proof, so this is genesis; but the previous address book does not hash to the genesis hash",
        ));
      }
      if next_ab_hash != prev_ab_hash {
        return Err(WrapsError::invalid_input(
          "a genesis step must rotate the address book onto itself",
        ));
      }
    }

    let message = Self::compute_rotation_message(&next_ab, hints_vk.as_ref())?;
    if !Self::verify_signature(&prev_ab, &message, multi_signature)? {
      return Err(WrapsError::invalid_input(
        "Schnorr multisignature verification failed",
      ));
    }

    let circuit = C {
      pc: Arc::clone(&pc),
      prev_ab,
      bitvector: *bitvector,
      sig: signature.clone(),
      msg: decode_rotation_message(&message)?,
    };

    let mut running = if is_genesis {
      // `RecursiveSNARK::new` already performs the first step's work; the `prove_step`
      // below is the one that commits to it.
      let z0 = vec![prev_ab_hash, hints_vk_hash];
      let snark = RecursiveSNARK::<E1, E2, C>::new(pp, &circuit, &z0)
        .map_err(|e| WrapsError::cryptography(format!("could not start the chain: {e}")))?;
      UncompressedWrapsProof {
        num_steps: snark.num_steps(),
        z0,
        zi: snark.outputs().to_vec(),
        snark,
      }
    } else {
      let running = decode::<UncompressedWrapsProof>(
        prev_proof
          .as_ref()
          .expect("checked by is_genesis above")
          .as_slice(),
      )?;
      // Reject inconsistent metadata before advancing and replacing the statement.
      if running.num_steps == 0
        || running.z0.len() != 2
        || running.zi.len() != 2
        || running.num_steps != running.snark.num_steps()
        || running.zi != running.snark.outputs()
      {
        return Err(WrapsError::invalid_input(
          "previous running proof metadata does not match its SNARK",
        ));
      }
      running
    };

    running
      .snark
      .prove_step(pp, &circuit)
      .map_err(|e| WrapsError::cryptography(format!("proving the rotation failed: {e}")))?;

    running.num_steps = running.snark.num_steps();
    running.zi = running
      .snark
      .verify(pp, running.num_steps, &running.z0)
      .map_err(|e| WrapsError::cryptography(format!("the running proof does not verify: {e}")))?;

    let snark = CompressedSNARK::<_, _, _, S1, S2>::prove(pp, pk, &running.snark)
      .map_err(|e| WrapsError::cryptography(format!("compressing the proof failed: {e}")))?;
    let compressed = encode(&CompressedWrapsProof {
      num_steps: running.num_steps,
      z0: running.z0.clone(),
      zi: running.zi.clone(),
      snark,
    })?;
    let uncompressed = encode(&running)?;

    // Check what we are about to hand out, against the key a verifier would use.
    let vk_bytes = Self::get_compressed_verification_key_bytes(vk)?;
    if !Self::verify_compressed_wraps_proof(
      &vk_bytes,
      &compressed,
      ab_genesis_hash,
      hints_vk.as_ref(),
    )? {
      return Err(WrapsError::cryptography(
        "the compressed proof just produced does not verify",
      ));
    }

    Ok((uncompressed, compressed))
  }

  /// Checks the running proof directly, without compressing it.
  ///
  /// Cheaper than producing and checking a compressed proof, but not succinct — the
  /// running proof is megabytes and carries full witnesses. Useful to a party that
  /// already holds the folding parameters and just wants to confirm a chain it was
  /// handed; a remote verifier should be given the compressed proof instead.
  pub fn verify_uncompressed_wraps_proof(
    pp: &PublicParams,
    running_proof: &Vec<u8>,
    ab_genesis_hash: &AddressBookHash<E2>,
    hints_vk: impl AsRef<[u8]>,
  ) -> Result<bool, WrapsError> {
    let running = decode::<UncompressedWrapsProof>(running_proof)?;

    if running.z0.len() != 2 || running.zi.len() != 2 || running.z0[0] != *ab_genesis_hash {
      return Ok(false);
    }

    match running.snark.verify(pp, running.num_steps, &running.z0) {
      Ok(zi) => Ok(zi == running.zi && zi[1] == Self::compute_hints_vk_hash(hints_vk)),
      Err(_) => Ok(false),
    }
  }

  /// Checks a compressed proof against a serialized verifier key.
  ///
  /// The proof uses plain bincode encoding; the verifier key uses zlib-compressed bincode.
  ///
  /// Beyond the SNARK itself this pins the two ends of the chain: it must start at
  /// `ab_genesis_hash` and must currently carry `hints_vk`. Without those a valid proof
  /// of some *other* chain would pass.
  pub fn verify_compressed_wraps_proof(
    compressed_vk_serialized: &Vec<u8>,
    proof_serialized: &Vec<u8>,
    ab_genesis_hash: &AddressBookHash<E2>,
    hints_vk: impl AsRef<[u8]>,
  ) -> Result<bool, WrapsError> {
    let vk = decode_compressed::<VerifierKey>(compressed_vk_serialized)?;
    let proof = decode::<CompressedWrapsProof>(proof_serialized)?;

    if proof.z0.len() != 2 || proof.zi.len() != 2 {
      return Ok(false);
    }
    // The chain starts at the genesis book, and currently carries the expected hints key.
    let genesis_ok = proof.z0[0] == *ab_genesis_hash;
    let hints_ok = proof.zi[1] == Self::compute_hints_vk_hash(hints_vk);

    // Nova returns the final state authenticated by the SNARK. It must agree with
    // the explicit `zi` used above to check the expected hints key.
    match proof.snark.verify(&vk, proof.num_steps, &proof.z0) {
      Ok(zi) => Ok(genesis_ok && hints_ok && zi == proof.zi),
      Err(_) => Ok(false),
    }
  }
}
