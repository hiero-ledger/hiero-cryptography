//! Bitvectors, serialization, seed derivation, and field representation utilities.

use crate::{
  constants::{ENTROPY_SIZE, MAX_AB_SIZE},
  error::WrapsError,
};
use ff::{Field, PrimeFieldBits};
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use nova_snark::{provider::traits::DlogGroup, traits::Engine};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Which members of an address book signed, always padded to [`MAX_AB_SIZE`].
///
/// Fixed width because it reaches the circuit, whose shape cannot depend on how large
/// the committee happens to be. Padding bits are false: a seat that does not exist did
/// not sign.
/// Construct from an array with `BitVector::from(bits)`. Serialization contains
/// exactly [`MAX_AB_SIZE`] booleans, without a vector length prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BitVector(#[serde(with = "serde_arrays")] [bool; MAX_AB_SIZE]);

impl From<[bool; MAX_AB_SIZE]> for BitVector {
  fn from(bits: [bool; MAX_AB_SIZE]) -> Self {
    Self(bits)
  }
}

impl AsRef<[bool]> for BitVector {
  fn as_ref(&self) -> &[bool] {
    &self.0
  }
}

impl std::ops::Deref for BitVector {
  type Target = [bool; MAX_AB_SIZE];

  fn deref(&self) -> &Self::Target {
    &self.0
  }
}

impl std::ops::DerefMut for BitVector {
  fn deref_mut(&mut self) -> &mut Self::Target {
    &mut self.0
  }
}

impl IntoIterator for BitVector {
  type Item = bool;
  type IntoIter = std::array::IntoIter<bool, MAX_AB_SIZE>;

  fn into_iter(self) -> Self::IntoIter {
    self.0.into_iter()
  }
}

/// Widens a caller's bitvector to [`MAX_AB_SIZE`], marking the padding seats absent.
pub(crate) fn pad_bitvector(bitvector: &[bool]) -> Result<BitVector, WrapsError> {
  if bitvector.len() > MAX_AB_SIZE {
    return Err(WrapsError::invalid_input(format!(
      "bitvector has {} bits, more than the {MAX_AB_SIZE} seats the circuit can take",
      bitvector.len()
    )));
  }

  Ok(BitVector::from(core::array::from_fn(|i| {
    bitvector.get(i).copied().unwrap_or(false)
  })))
}

/// Serializes a value with the bincode configuration the rest of the crate uses.
///
/// Uses bincode's legacy configuration without compression.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, WrapsError> {
  bincode::serde::encode_to_vec(value, bincode::config::legacy())
    .map_err(|e| WrapsError::cryptography(format!("serialization failed: {e}")))
}

/// The inverse of [`encode`].
///
/// Rejects trailing bytes. Deserialization restores the value's representation;
/// callers are responsible for validating its meaning.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, WrapsError> {
  let (value, consumed) = bincode::serde::decode_from_slice(bytes, bincode::config::legacy())
    .map_err(|e| WrapsError::cryptography(format!("deserialization failed: {e}")))?;
  if consumed != bytes.len() {
    return Err(WrapsError::invalid_input(
      "trailing bytes after serialized value",
    ));
  }
  Ok(value)
}

/// Serializes a value with bincode and compresses it with zlib.
pub(crate) fn encode_compressed<T: Serialize>(value: &T) -> Result<Vec<u8>, WrapsError> {
  let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
  bincode::serde::encode_into_std_write(value, &mut encoder, bincode::config::legacy())
    .map_err(|e| WrapsError::cryptography(format!("serialization failed: {e}")))?;

  encoder
    .finish()
    .map_err(|e| WrapsError::cryptography(format!("deflate failed: {e}")))
}

/// The inverse of [`encode_compressed`].
pub(crate) fn decode_compressed<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, WrapsError> {
  let mut decoder = ZlibDecoder::new(bytes);

  bincode::serde::decode_from_std_read(&mut decoder, bincode::config::legacy())
    .map_err(|e| WrapsError::cryptography(format!("deserialization failed: {e}")))
}

/// Derives two seeds as SHA256(seed || counter), using one-byte counters 0 and 1.
pub(crate) fn expand_seed(seed: [u8; ENTROPY_SIZE]) -> [[u8; ENTROPY_SIZE]; 2] {
  core::array::from_fn(|counter| {
    let mut hasher = Sha256::new();
    hasher.update(seed);
    hasher.update([counter as u8]);
    hasher.finalize().into()
  })
}

/// Returns the low `num_bits` bits of the canonical representation of `x`.
pub(crate) fn le_bits_of<F: PrimeFieldBits>(x: &F, num_bits: usize) -> Vec<bool> {
  let bits = x.to_le_bits();
  (0..num_bits).map(|i| bits[i]).collect()
}

/// Whether `x` is below `2^num_bits`.
#[cfg(test)]
pub(crate) fn fits_in_bits<F: PrimeFieldBits>(x: &F, num_bits: usize) -> bool {
  x.to_le_bits().iter().skip(num_bits).all(|bit| !bit)
}

/// Encodes a group element as affine coordinates followed by the infinity flag.
pub(crate) fn encode_point<E: Engine>(p: &E::GE) -> [E::Base; 3]
where
  E::GE: DlogGroup,
{
  let (x, y, is_infinity) = p.to_coordinates();
  [
    x,
    y,
    if is_infinity {
      E::Base::ONE
    } else {
      E::Base::ZERO
    },
  ]
}
