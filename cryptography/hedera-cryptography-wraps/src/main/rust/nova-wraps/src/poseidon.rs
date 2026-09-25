//! Native Poseidon hashing and shared constants.

use crate::wraps::Base;
use ff::PrimeField;
use generic_array::typenum::U32;
use nova_snark::frontend::gadgets::poseidon::{
  IOPattern, PoseidonConstants, Simplex, Sponge, SpongeAPI, SpongeOp, SpongeTrait, Strength,
};
use std::sync::{Arc, OnceLock};

/// Poseidon constants shared by the native and in-circuit hashes.
///
/// Rate 32 (width 33) is chosen for the address-book hash: at
/// 5 · [`crate::constants::MAX_AB_SIZE`] = 320 absorbed elements — five per entry, see
/// [`crate::wraps::hash_address_book`] — it needs 10 permutations, which measures
/// cheapest across the arities the gadget supports.
pub(crate) type Constants<F> = PoseidonConstants<F, U32>;

fn constants<F: PrimeField>() -> Constants<F> {
  Sponge::<F, U32>::api_constants(Strength::Standard)
}

/// The process-wide Poseidon constants.
///
/// Generating them for width 33 costs ~180 ms, so they are built once and shared;
/// building them inside `synthesize` would pay that on every proof step.
pub(crate) fn shared_constants() -> Arc<Constants<Base>> {
  static PC: OnceLock<Arc<Constants<Base>>> = OnceLock::new();
  PC.get_or_init(|| Arc::new(constants::<Base>())).clone()
}

/// Absorbs `elements` under `domain_sep` and squeezes a single field element.
pub(crate) fn poseidon_native<F: PrimeField>(
  pc: &Constants<F>,
  domain_sep: u32,
  elements: &[F],
) -> F {
  let num_absorbs = elements.len() as u32;
  let pattern = IOPattern(vec![SpongeOp::Absorb(num_absorbs), SpongeOp::Squeeze(1u32)]);

  let mut sponge = Sponge::new_with_constants(pc, Simplex);
  let acc = &mut ();

  sponge.start(pattern, Some(domain_sep), acc);
  SpongeAPI::absorb(&mut sponge, num_absorbs, elements, acc);
  let hash = SpongeAPI::squeeze(&mut sponge, 1, acc);
  sponge.finish(acc).unwrap();

  hash[0]
}
