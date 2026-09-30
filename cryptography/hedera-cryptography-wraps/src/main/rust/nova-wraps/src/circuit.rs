//! Rotation circuit and reusable circuit constraints.

use crate::{
  constants::{DS_ADDRESS_BOOK, DS_CHALLENGE, MAX_AB_SIZE, NUM_CHALLENGE_BITS, WEIGHT_BITS},
  poseidon::Constants,
  schnorr::{Keypair, Schnorr, SchnorrSecretKey, Signature},
  utils::{le_bits_of, BitVector},
  wraps::{AddressBook, AddressBookHash, HintsVKHash, RotationMessage},
};
use ff::{Field, PrimeField, PrimeFieldBits};
use nova_snark::{
  frontend::{
    gadgets::poseidon::{Elt, IOPattern, Simplex, SpongeAPI, SpongeCircuit, SpongeOp, SpongeTrait},
    num::AllocatedNum,
    AllocatedBit, Boolean, ConstraintSystem, SynthesisError,
  },
  gadgets::{
    ecc::AllocatedPoint,
    utils::{alloc_zero, le_bits_to_num},
  },
  provider::traits::DlogGroup,
  traits::{circuit::StepCircuit, Engine},
};
use rand_core::OsRng;
use std::sync::Arc;

/// The in-circuit counterpart of [`crate::poseidon::poseidon_native`].
fn poseidon_circuit<F, CS>(
  cs: &mut CS,
  pc: &Constants<F>,
  domain_sep: u32,
  elements: &[AllocatedNum<F>],
) -> Result<AllocatedNum<F>, SynthesisError>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  let num_absorbs = elements.len() as u32;
  let pattern = IOPattern(vec![SpongeOp::Absorb(num_absorbs), SpongeOp::Squeeze(1u32)]);
  let elts = elements
    .iter()
    .cloned()
    .map(Elt::Allocated)
    .collect::<Vec<_>>();

  let mut ns = cs.namespace(|| "poseidon");
  let hash = {
    let mut sponge = SpongeCircuit::new_with_constants(pc, Simplex);
    let acc = &mut ns;

    sponge.start(pattern, Some(domain_sep), acc);
    SpongeAPI::absorb(&mut sponge, num_absorbs, &elts, acc);
    let hash = SpongeAPI::squeeze(&mut sponge, 1, acc);
    sponge.finish(acc).unwrap();
    hash
  };

  let hash = Elt::ensure_allocated(&hash[0], &mut ns.namespace(|| "ensure allocated"));
  hash
}

/// The in-circuit counterpart of `schnorr::truncate_to_challenge`.
fn truncate_to_challenge_circuit<F, CS>(
  mut cs: CS,
  x: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError>
where
  F: PrimeField + PrimeFieldBits,
  CS: ConstraintSystem<F>,
{
  // `to_bits_le_strict` pins down the canonical representation, so taking a prefix of
  // the bits is unambiguous.
  let bits = x.to_bits_le_strict(cs.namespace(|| "strict bits"))?;
  let low = bits[..NUM_CHALLENGE_BITS]
    .iter()
    .map(|b| match b {
      Boolean::Is(bit) => bit.clone(),
      _ => panic!("to_bits_le_strict returns allocated bits"),
    })
    .collect::<Vec<AllocatedBit>>();

  le_bits_to_num(cs.namespace(|| "recompose"), &low)
}

/// Allocates `bits` as booleanity-constrained circuit variables.
fn alloc_bits<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  bits: &[bool],
) -> Result<Vec<AllocatedBit>, SynthesisError> {
  bits
    .iter()
    .enumerate()
    .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("bit {i}")), Some(*b)))
    .collect()
}

/// Enforces `a == b`.
fn enforce_equal<F: PrimeField, CS: ConstraintSystem<F>>(
  cs: &mut CS,
  annotation: &'static str,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
) {
  cs.enforce(
    || annotation,
    |lc| lc + a.get_variable() - b.get_variable(),
    |lc| lc + CS::one(),
    |lc| lc,
  );
}

/// Allocates the sum of `terms`.
fn sum_of<F, CS>(mut cs: CS, terms: &[AllocatedNum<F>]) -> Result<AllocatedNum<F>, SynthesisError>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  let value = terms
    .iter()
    .try_fold(F::ZERO, |acc, term| Some(acc + term.get_value()?));
  let sum = AllocatedNum::alloc(cs.namespace(|| "sum"), || {
    value.ok_or(SynthesisError::AssignmentMissing)
  })?;
  cs.enforce(
    || "sum equals its terms",
    |mut lc| {
      for term in terms {
        lc = lc + term.get_variable();
      }
      lc
    },
    |lc| lc + CS::one(),
    |lc| lc + sum.get_variable(),
  );

  Ok(sum)
}

/// Enforces `a > b`, given that both are known to be below `2^bound_bits`.
///
/// R1CS has no ordering — its values are residues, not integers — so a comparison is
/// always a bounded-difference argument: `a > b` exactly when `a - b - 1` is a
/// non-negative integer, and "non-negative" only means something relative to a bound.
/// That is what the range check supplies. If `a <= b` the difference is negative, which
/// as a field element sits up near the modulus and has no `bound_bits`-bit
/// decomposition, so the constraint system becomes unsatisfiable.
///
/// The caller owes the precondition: operands at or above `2^bound_bits` can wrap into
/// the range and compare wrongly.
fn enforce_greater_than<F, CS>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
  bound_bits: usize,
) -> Result<(), SynthesisError>
where
  F: PrimeField + PrimeFieldBits,
  CS: ConstraintSystem<F>,
{
  let difference = AllocatedNum::alloc(cs.namespace(|| "a - b - 1"), || {
    let a = a.get_value().ok_or(SynthesisError::AssignmentMissing)?;
    let b = b.get_value().ok_or(SynthesisError::AssignmentMissing)?;
    Ok(a - b - F::ONE)
  })?;
  cs.enforce(
    || "difference is a - b - 1",
    |lc| lc + a.get_variable() - b.get_variable() - CS::one(),
    |lc| lc + CS::one(),
    |lc| lc + difference.get_variable(),
  );

  enforce_range(
    cs.namespace(|| "a - b - 1 is not negative"),
    &difference,
    bound_bits,
  )
}

/// Enforces `0 <= value < 2^num_bits`.
///
/// A value the prover cannot decompose into `num_bits` bits — anything at or above the
/// bound, including a field element standing in for a negative number — leaves the
/// recomposition constraint unsatisfiable.
fn enforce_range<F, CS>(
  mut cs: CS,
  value: &AllocatedNum<F>,
  num_bits: usize,
) -> Result<(), SynthesisError>
where
  F: PrimeField + PrimeFieldBits,
  CS: ConstraintSystem<F>,
{
  let bits = value.get_value().map(|v| le_bits_of(&v, num_bits));
  let allocated = (0..num_bits)
    .map(|i| {
      AllocatedBit::alloc(
        cs.namespace(|| format!("bit {i}")),
        bits.as_ref().map(|b| b[i]),
      )
    })
    .collect::<Result<Vec<_>, _>>()?;
  let recomposed = le_bits_to_num(cs.namespace(|| "recompose"), &allocated)?;
  enforce_equal(&mut cs, "value fits in the range", value, &recomposed);

  Ok(())
}

/// One rotation: check the advised address book against the running state, aggregate the
/// signing subset into a joint key, verify the committee's signature on the next state,
/// and output that state.
#[derive(Clone, Debug)]
// This type must be public because it is part of the public Nova parameter/key aliases.
// Its private fields keep circuit construction inside WRAPS.
#[doc(hidden)]
pub struct RotationCircuit<E: Engine> {
  /// Shared so that the width-33 Poseidon constants are built once, not per step.
  pub(crate) pc: Arc<Constants<E::Base>>,
  /// The address book in force at this step.
  pub(crate) prev_ab: AddressBook<E>,
  /// Which of its members signed.
  pub(crate) bitvector: BitVector,
  /// Their aggregate signature on the rotation message.
  pub(crate) sig: Signature<E>,
  /// The rotation message: the next book's hash and the next hints vk hash.
  pub(crate) msg: RotationMessage<E>,
}

impl<E: Engine> RotationCircuit<E>
where
  E::GE: DlogGroup,
{
  /// A circuit with a well-formed but meaningless witness, for shape synthesis.
  ///
  /// The shape does not depend on the witness, but the dummy still satisfies its own
  /// constraints: every seat signs, every weight is 1, and the signature is produced
  /// under the joint secret key, so it is a usable smoke test as well as a shape.
  pub(crate) fn dummy(pc: &Arc<Constants<E::Base>>) -> Self {
    let keypairs = (0..MAX_AB_SIZE)
      .map(|_| Schnorr::<E>::keygen(&mut OsRng))
      .collect::<Vec<_>>();
    let prev_ab: AddressBook<E> = keypairs
      .iter()
      .enumerate()
      .map(|(i, kp)| {
        (
          <E as Engine>::Base::from(i as u64),
          (kp.pk, Schnorr::<E>::prove_knowledge(kp, &mut OsRng)),
          1,
        )
      })
      .collect();

    let joint = Keypair {
      sk: keypairs
        .iter()
        .fold(SchnorrSecretKey::<E>::ZERO, |acc, kp| acc + kp.sk),
      pk: keypairs
        .iter()
        .skip(1)
        .fold(keypairs[0].pk, |acc, kp| acc + kp.pk),
    };
    let msg = [<E as Engine>::Base::ZERO, <E as Engine>::Base::ONE];
    let sig = Schnorr::<E>::sign(pc, &joint, &msg);

    Self {
      pc: Arc::clone(pc),
      prev_ab,
      bitvector: [true; MAX_AB_SIZE].into(),
      sig,
      msg,
    }
  }
}

impl<E: Engine> StepCircuit<E::Base> for RotationCircuit<E>
where
  E::GE: DlogGroup,
{
  fn arity(&self) -> usize {
    2
  }

  fn synthesize<CS: ConstraintSystem<E::Base>>(
    &self,
    cs: &mut CS,
    z_in: &[AllocatedNum<E::Base>],
  ) -> Result<Vec<AllocatedNum<E::Base>>, SynthesisError> {
    assert_eq!(z_in.len(), 2);
    assert_eq!(
      self.prev_ab.len(),
      MAX_AB_SIZE,
      "the circuit takes a padded address book"
    );
    let pc = Arc::clone(&self.pc);

    // ---------------------------------------------------------------------
    // Advice: the address book in force at this step.
    // ---------------------------------------------------------------------
    let mut keys = Vec::with_capacity(MAX_AB_SIZE);
    let mut weights = Vec::with_capacity(MAX_AB_SIZE);
    let mut node_ids = Vec::with_capacity(MAX_AB_SIZE);
    for (i, (node_id, (pk, _pok), weight)) in self.prev_ab.iter().enumerate() {
      let point = AllocatedPoint::<E>::alloc(
        cs.namespace(|| format!("alloc pk {i}")),
        Some(pk.to_coordinates()),
      )?;
      // The keys are prover-supplied, so each has to be constrained to the curve before
      // it is fed to the group law. The point at infinity is *allowed* here: it is what
      // an empty seat holds, and the effective-weight step below strips its weight, so a
      // seat nobody can sign for cannot carry weight anyone can claim. What the circuit
      // does not check is that non-identity keys are unique and come with proofs of
      // possession — `verify_address_book` does that before a book is signed into the
      // chain. See the crate-level "Trust boundary".
      point.check_on_curve(cs.namespace(|| format!("pk {i} on curve")))?;

      keys.push(point);
      let allocated_weight = AllocatedNum::alloc(cs.namespace(|| format!("weight {i}")), || {
        Ok(E::Base::from(*weight))
      })?;
      // Range constraints apply to every seat, including identity seats. Rust's u64
      // type bounds honest inputs; these constraints also bind a malicious witness.
      enforce_range(
        cs.namespace(|| format!("weight {i} fits in 64 bits")),
        &allocated_weight,
        WEIGHT_BITS,
      )?;
      weights.push(allocated_weight);
      node_ids.push(AllocatedNum::alloc(
        cs.namespace(|| format!("node id {i}")),
        || Ok(*node_id),
      )?);
    }

    // ---------------------------------------------------------------------
    // Check 1: the advised book is the one the running state commits to.
    // ---------------------------------------------------------------------
    // The same five-element-per-entry layout `hash_address_book` uses: node id, the key
    // as `(x, y, is_infinity)`, then weight.
    let preimage = node_ids
      .iter()
      .zip(keys.iter())
      .zip(weights.iter())
      .flat_map(|((node_id, pk), weight)| {
        [
          node_id.clone(),
          pk.x.clone(),
          pk.y.clone(),
          pk.is_infinity.clone(),
          weight.clone(),
        ]
      })
      .collect::<Vec<_>>();
    let h_ab = poseidon_circuit(
      &mut cs.namespace(|| "H(ab)"),
      &pc,
      DS_ADDRESS_BOOK,
      &preimage,
    )?;
    enforce_equal(cs, "H(ab) == z_in[0]", &h_ab, &z_in[0]);

    // ---------------------------------------------------------------------
    // Advice: which members signed.
    // ---------------------------------------------------------------------
    // Free advice, and deliberately so: choosing a subset the prover cannot sign for
    // only makes the signature check below fail.
    let bits = alloc_bits(cs.namespace(|| "bitvector"), self.bitvector.as_ref())?;

    // ---------------------------------------------------------------------
    // Effective weights: a seat keyed to the point at infinity carries none.
    // ---------------------------------------------------------------------
    // The identity is the additive unit, so a seat holding it contributes nothing to
    // the joint key aggregated below — which means anyone can "sign" for it. Counting
    // its weight would hand that weight to whoever claims the seat, so the circuit
    // zeroes it here, before either sum is taken.
    //
    // Excluded from the *total* as well as from the signing subset, which is what makes
    // an empty seat equivalent to a seat that does not exist: padding a book out to
    // `MAX_AB_SIZE` cannot move the threshold, and dead weight cannot raise the bar.
    //
    // `is_infinity` is trustworthy here even though the whole entry is prover advice.
    // `AllocatedPoint::alloc` constrains it to a bit, `check_on_curve` above ties it to
    // the coordinates, and `H(ab)` covers it — so a prover can neither raise nor lower
    // the flag on a seat without breaking the hash check.
    //
    // [`subset_weight`] applies the same rule natively, so the two agree on any book,
    // including one that never went through [`verify_address_book`].
    let mut effective_weights = Vec::with_capacity(MAX_AB_SIZE);
    for i in 0..MAX_AB_SIZE {
      let effective =
        AllocatedNum::alloc(cs.namespace(|| format!("effective weight {i}")), || {
          Ok(if self.prev_ab[i].1 .0.to_coordinates().2 {
            <E as Engine>::Base::ZERO
          } else {
            E::Base::from(self.prev_ab[i].2)
          })
        })?;
      cs.enforce(
        || format!("effective weight {i} = weight * (1 - is_infinity)"),
        |lc| lc + weights[i].get_variable(),
        |lc| lc + CS::one() - keys[i].is_infinity.get_variable(),
        |lc| lc + effective.get_variable(),
      );
      effective_weights.push(effective);
    }

    // ---------------------------------------------------------------------
    // Check 2: the signing subset carries more than half of the total weight.
    // ---------------------------------------------------------------------
    let mut masked_weights = Vec::with_capacity(MAX_AB_SIZE);
    for i in 0..MAX_AB_SIZE {
      let masked = AllocatedNum::alloc(cs.namespace(|| format!("masked weight {i}")), || {
        let effective = effective_weights[i]
          .get_value()
          .ok_or(SynthesisError::AssignmentMissing)?;
        Ok(if self.bitvector[i] {
          effective
        } else {
          <E as Engine>::Base::ZERO
        })
      })?;
      cs.enforce(
        || format!("masked weight {i} = bit * effective weight"),
        |lc| lc + bits[i].get_variable(),
        |lc| lc + effective_weights[i].get_variable(),
        |lc| lc + masked.get_variable(),
      );
      masked_weights.push(masked);
    }

    // The majority rule, and the one property here that no native check can stand in
    // for: the bitvector is fresh advice at every step, so unlike the address book it
    // was never validated by anyone before reaching the circuit.
    let signing_weight = sum_of(cs.namespace(|| "signing weight"), &masked_weights)?;
    let total_weight = sum_of(cs.namespace(|| "total weight"), &effective_weights)?;
    enforce_range(
      cs.namespace(|| "total weight fits in 64 bits"),
      &total_weight,
      WEIGHT_BITS,
    )?;
    // Both subset sums are nonnegative and at most the bounded total. Comparing
    // signing against the remaining weight gives the strict majority without doubling.
    let remaining_weight = AllocatedNum::alloc(cs.namespace(|| "remaining weight"), || {
      let total = total_weight
        .get_value()
        .ok_or(SynthesisError::AssignmentMissing)?;
      let signing = signing_weight
        .get_value()
        .ok_or(SynthesisError::AssignmentMissing)?;
      Ok(total - signing)
    })?;
    cs.enforce(
      || "remaining weight = total - signing",
      |lc| lc + total_weight.get_variable() - signing_weight.get_variable(),
      |lc| lc + CS::one(),
      |lc| lc + remaining_weight.get_variable(),
    );
    enforce_greater_than(
      cs.namespace(|| "the signing subset holds a majority of the weight"),
      &signing_weight,
      &remaining_weight,
      WEIGHT_BITS,
    )?;

    // ---------------------------------------------------------------------
    // Aggregate the signing subset into the joint key.
    // ---------------------------------------------------------------------
    // A seat the bitvector leaves out contributes the identity, so the sum runs over the
    // subset alone — matching what the signers used to derive their challenge, and what
    // `verify_signature` checks against. `AllocatedPoint::add` rather than
    // `add_incomplete`: the latter ties the chord slope to its inputs with the single
    // constraint `λ·(x₂ - x₁) = y₂ - y₁`, which for two equal keys degenerates to
    // `0 = 0` and leaves `λ` free, letting a prover steer the joint key at will.
    let mut pk = AllocatedPoint::<E>::default(cs.namespace(|| "joint key starts empty"))?;
    for i in 0..MAX_AB_SIZE {
      let masked = AllocatedPoint::<E>::select_point_or_infinity(
        cs.namespace(|| format!("mask pk {i}")),
        &keys[i],
        &Boolean::from(bits[i].clone()),
      )?;
      pk = pk.add(cs.namespace(|| format!("aggregate pk {i}")), &masked)?;
    }
    // Nonidentity seat keys can cancel in the selected sum. Its aggregate secret
    // would then be zero, allowing anyone to forge the committee's signature.
    cs.enforce(
      || "joint signing key is not infinity",
      |lc| lc + pk.is_infinity.get_variable(),
      |lc| lc + CS::one(),
      |lc| lc,
    );

    // ---------------------------------------------------------------------
    // Advice: the rotation message, and the signature over it.
    // ---------------------------------------------------------------------
    let next_ab_hash: AllocatedNum<AddressBookHash<E>> =
      AllocatedNum::alloc(cs.namespace(|| "next ab hash"), || Ok(self.msg[0]))?;
    let next_hints_vk_hash: AllocatedNum<HintsVKHash<E>> =
      AllocatedNum::alloc(cs.namespace(|| "next hints vk hash"), || Ok(self.msg[1]))?;

    // `s` is a full-width `E::Scalar`. It is not compared against anything else in the
    // circuit, so the bits are simply existentially quantified: the relation proved is
    // "there exists a scalar `s` such that ...", which is exactly what Schnorr asks.
    let s_bits = alloc_bits(
      cs.namespace(|| "s bits"),
      &le_bits_of(&self.sig.s, <E::Scalar as PrimeField>::NUM_BITS as usize),
    )?;
    // `e`, by contrast, is compared against the recomputed challenge below, so it must
    // be pinned to `NUM_CHALLENGE_BITS` bits: at that width the bit decomposition and
    // the field element determine each other, in both fields of the cycle.
    let e_bits = alloc_bits(
      cs.namespace(|| "e bits"),
      &le_bits_of(&self.sig.e, NUM_CHALLENGE_BITS),
    )?;
    let e = le_bits_to_num(cs.namespace(|| "e"), &e_bits)?;

    // ---------------------------------------------------------------------
    // Check 3: the signature verifies, i.e. e == H(pk, s·G - e·pk, msg).
    // ---------------------------------------------------------------------
    // The generator is a circuit constant; if the prover could choose it, it could pick
    // one whose discrete log relative to `pk` it knows.
    let (gen_x, gen_y, gen_is_infinity) = E::GE::gen().to_coordinates();
    assert!(!gen_is_infinity, "the generator is not the identity");
    let zero = alloc_zero(cs.namespace(|| "G is not infinity"));
    let g = AllocatedPoint::<E>::alloc_constant(cs.namespace(|| "G"), (gen_x, gen_y), zero)?;

    let s_g = g.scalar_mul(cs.namespace(|| "s * G"), &s_bits)?;
    let e_pk = pk.scalar_mul(cs.namespace(|| "e * pk"), &e_bits)?;
    let neg_e_pk = e_pk.negate(cs.namespace(|| "-(e * pk)"))?;
    let r = s_g.add(cs.namespace(|| "s * G - e * pk"), &neg_e_pk)?;

    let hash = poseidon_circuit(
      &mut cs.namespace(|| "H(pk, r, msg)"),
      &pc,
      DS_CHALLENGE,
      &[
        pk.x.clone(),
        pk.y.clone(),
        pk.is_infinity.clone(),
        r.x.clone(),
        r.y.clone(),
        r.is_infinity.clone(),
        next_ab_hash.clone(),
        next_hints_vk_hash.clone(),
      ],
    )?;
    let e_expected = truncate_to_challenge_circuit(cs.namespace(|| "truncate challenge"), &hash)?;
    enforce_equal(cs, "recomputed challenge matches e", &e, &e_expected);

    // ---------------------------------------------------------------------
    // Output the next state, which the following step will bind to its own book.
    // ---------------------------------------------------------------------
    // `z_in[1]`, the previous hints vk hash, is carried but never checked: the hints key
    // is an opaque payload the chain transports, not something the circuit reasons about.
    Ok(vec![next_ab_hash, next_hints_vk_hash])
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::wraps::Base;
  use nova_snark::frontend::util_cs::test_cs::TestConstraintSystem;

  #[test]
  fn weight_range_accepts_exactly_u64_values() {
    for (value, expected) in [
      (Base::ZERO, true),
      (Base::from(u64::MAX), true),
      (Base::from(u64::MAX) + Base::ONE, false),
      (-Base::ONE, false),
    ] {
      let mut cs = TestConstraintSystem::<Base>::new();
      let weight = AllocatedNum::alloc(cs.namespace(|| "weight"), || Ok(value)).unwrap();
      enforce_range(cs.namespace(|| "weight range"), &weight, WEIGHT_BITS).unwrap();
      assert_eq!(cs.is_satisfied(), expected);
    }
  }
}
