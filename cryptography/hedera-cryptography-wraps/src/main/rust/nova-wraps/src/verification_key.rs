//! Compact verifier-key export for WRAPS' Mercury/MicroSpartan profile.
//!
//! Used by `WRAPS::get_compressed_verification_key` to derive a stock Nova key
//! from public parameters and export its 778-byte descriptor. This module does
//! not import descriptors or construct prepared verification keys.
//!
//! Export is pinned to `nova-snark = 0.76.0`, its non-EVM Serde layout, and legacy
//! bincode. The private-field mirrors below follow, in order:
//! `nova::VerifierKey` (`src/nova/mod.rs`), then
//! `spartan::ppsnark::VerifierKey` (`src/spartan/ppsnark.rs`). PhantomData and
//! skipped digest caches have no wire fields. The public stock IPA verifier-key
//! type is used directly. The mirror must reproduce the exact stock encoding.
//! A Nova, curve, circuit, codec, or feature-layout change requires review and a
//! new format version; the length checks fail closed.
//!
//! Export checks the fixed profile, default Poseidon constants, and complete
//! canonical Grumpkin IPA key before omitting those deterministic values. The
//! ceremony-dependent Mercury PCS verifier key, shape commitments,
//! public-parameter digest and derandomization keys remain in the descriptor.

use crate::{
  error::WrapsError,
  utils::{decode, encode},
  wraps::{NovaVerifierKey, PublicParams, E1, E2, EE2, S1, S2},
  RotationCircuit,
};
use nova_snark::{
  nova::CompressedSNARK,
  provider::{hyperkzg, ipa_pc, pedersen},
  spartan::ppsnark::R1CSShapeSparkCommitment,
  traits::{
    commitment::CommitmentEngineTrait, evaluation::EvaluationEngineTrait, Engine, ROConstants,
  },
};
use serde::{Deserialize, Serialize};

// This is deliberately distinct from the research HyperKZG-compatible format.
pub(crate) const MAGIC: [u8; 8] = *b"WRPMVK01";
pub(crate) const VERSION: u16 = 1;
pub(crate) const WIRE_BYTES: usize = 778;
const STOCK_BYTES: usize = 4_738_776;
pub(crate) const ARITY: usize = 2;
pub(crate) const PRIMARY_DIMENSION: usize = 32_768;
pub(crate) const PRIMARY_DOMAIN: usize = 1_048_576;
pub(crate) const SECONDARY_DIMENSION: usize = 16_384;
pub(crate) const SECONDARY_GENERATORS: usize = 131_072;

pub(crate) type PrimaryScalar = <E1 as Engine>::Scalar;
type IpaVerifierKey = ipa_pc::VerifierKey<E2>;

// Nova ppSNARK VK: num_cons, num_vars, vk_ee, S_comm; digest is skipped.
#[derive(Serialize, Deserialize)]
pub(crate) struct PrimaryMirror {
  pub(crate) num_cons: usize,
  pub(crate) num_vars: usize,
  pub(crate) vk_ee: hyperkzg::VerifierKey<E1>, // Mercury uses this exact public VK type.
  pub(crate) shape_commitment: R1CSShapeSparkCommitment<E1>,
}

#[derive(Serialize, Deserialize)]
struct SecondaryMirror {
  num_cons: usize,
  num_vars: usize,
  vk_ee: IpaVerifierKey,
  shape_commitment: R1CSShapeSparkCommitment<E2>,
}

// Nova outer VK: F_arity, two RO constants, pp_digest, two SNARK VKs, two DKs.
#[derive(Serialize, Deserialize)]
struct FullMirror {
  arity: usize,
  ro_primary: ROConstants<E1>,
  ro_secondary: ROConstants<E2>,
  pp_digest: PrimaryScalar,
  primary: PrimaryMirror,
  secondary: SecondaryMirror,
  dk_primary: hyperkzg::DerandKey<E1>,
  dk_secondary: pedersen::DerandKey<E2>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct CompactSecondary {
  pub(crate) num_cons: usize,
  pub(crate) num_vars: usize,
  pub(crate) shape_commitment: R1CSShapeSparkCommitment<E2>,
  pub(crate) generator_count: u64,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Descriptor {
  pub(crate) magic: [u8; 8],
  pub(crate) version: u16,
  pub(crate) arity: usize,
  pub(crate) pp_digest: PrimaryScalar,
  pub(crate) primary: PrimaryMirror,
  pub(crate) secondary: CompactSecondary,
  pub(crate) dk_primary: hyperkzg::DerandKey<E1>,
  pub(crate) dk_secondary: pedersen::DerandKey<E2>,
}

fn invalid(message: &str) -> WrapsError {
  WrapsError::invalid_input(format!("compact verifier key: {message}"))
}

fn layout_error(message: &str) -> WrapsError {
  WrapsError::cryptography(format!(
    "Nova 0.76.0 verifier-key layout mismatch: {message}"
  ))
}

fn validate_descriptor(descriptor: &Descriptor) -> Result<(), WrapsError> {
  if descriptor.magic != MAGIC || descriptor.version != VERSION {
    return Err(invalid("unsupported Mercury format or version"));
  }
  if descriptor.arity != ARITY {
    return Err(invalid("unsupported circuit arity"));
  }
  if descriptor.primary.num_cons != PRIMARY_DIMENSION
    || descriptor.primary.num_vars != PRIMARY_DIMENSION
    || descriptor.primary.shape_commitment.N != PRIMARY_DOMAIN
  {
    return Err(invalid("unsupported primary MicroSpartan dimensions"));
  }
  if descriptor.secondary.num_cons != SECONDARY_DIMENSION
    || descriptor.secondary.num_vars != SECONDARY_DIMENSION
    || descriptor.secondary.shape_commitment.N != SECONDARY_GENERATORS
    || descriptor.secondary.generator_count != SECONDARY_GENERATORS as u64
  {
    return Err(invalid("unsupported secondary MicroSpartan dimensions"));
  }
  Ok(())
}

fn canonical_ipa_key() -> Result<IpaVerifierKey, WrapsError> {
  let ck = <E2 as Engine>::CE::setup(b"ck", SECONDARY_GENERATORS)
    .map_err(|error| WrapsError::cryptography(format!("IPA generator setup failed: {error}")))?;
  let (_, vk) = EE2::setup(&ck)
    .map_err(|error| WrapsError::cryptography(format!("IPA verifier setup failed: {error}")))?;
  // Stock IPA setup also constructs its auxiliary b"ipa" commitment key.
  Ok(vk)
}

/// Derive the compressed-proof verifier key and export its compact descriptor.
pub(crate) fn export(pp: &PublicParams) -> Result<Vec<u8>, WrapsError> {
  let (_, vk) = CompressedSNARK::<E1, E2, RotationCircuit<E2>, S1, S2>::setup(pp)
    .map_err(|error| WrapsError::cryptography(format!("verifier setup failed: {error}")))?;
  compact_stock_key(&vk)
}

fn compact_stock_key(vk: &NovaVerifierKey) -> Result<Vec<u8>, WrapsError> {
  let original_bytes = encode(vk)?;
  if original_bytes.len() != STOCK_BYTES {
    return Err(layout_error(
      "unexpected full key size or unsupported profile",
    ));
  }
  let full: FullMirror = decode(&original_bytes)?;
  if encode(&full)? != original_bytes {
    return Err(layout_error("full key mirror does not round-trip"));
  }
  // Poseidon Serde omits its unused round_constants cache. Native PartialEq is
  // therefore unsuitable after a round-trip: compare all serialized data.
  if encode(&full.ro_primary)? != encode(&ROConstants::<E1>::default())?
    || encode(&full.ro_secondary)? != encode(&ROConstants::<E2>::default())?
  {
    return Err(invalid("Poseidon constants differ from the fixed defaults"));
  }

  let descriptor = Descriptor {
    magic: MAGIC,
    version: VERSION,
    arity: full.arity,
    pp_digest: full.pp_digest,
    primary: full.primary,
    secondary: CompactSecondary {
      num_cons: full.secondary.num_cons,
      num_vars: full.secondary.num_vars,
      shape_commitment: full.secondary.shape_commitment,
      generator_count: SECONDARY_GENERATORS as u64,
    },
    dk_primary: full.dk_primary,
    dk_secondary: full.dk_secondary,
  };
  validate_descriptor(&descriptor)?;
  // Compare the entire IPA VK, including h and both auxiliary-key generators;
  // matching only the generator count would not justify omitting these bytes.
  if encode(&full.secondary.vk_ee)? != encode(&canonical_ipa_key()?)? {
    return Err(invalid("IPA key differs from canonical stock setup"));
  }
  let bytes = encode(&descriptor)?;
  if bytes.len() != WIRE_BYTES {
    return Err(layout_error("compact descriptor is not 778 bytes"));
  }
  Ok(bytes)
}
