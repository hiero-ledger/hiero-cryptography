// SPDX-License-Identifier: Apache-2.0

use ark_bls12_381::Fq;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::CanonicalDeserialize;
use jni::JNIEnv;
use jni::objects::{JByteArray, JObject};
use jni::sys::jbyteArray;
use crate::hints::{G1AffinePoint, G2AffinePoint};
use crate::jni_util;

/// Returns the big-endian byte representation of an Fq field element, left-padded to 48 bytes.
/// into_bigint() converts out of Montgomery form; to_bytes_be() gives the canonical integer bytes.
/// Explicit padding guards against to_bytes_be() returning fewer than 48 bytes for small values.
fn fq_to_be48(fq: &Fq) -> [u8; 48] {
    let bytes = fq.into_bigint().to_bytes_be();
    assert!(
        bytes.len() <= 48,
        "BLS12-381 field element cannot exceed 48 bytes"
    );
    let mut result = [0u8; 48];
    result[48 - bytes.len()..].copy_from_slice(&bytes);
    result
}

/// Converts a G1 affine point to the 128-byte EIP-2537 encoding:
///   [16 zeros | x (48 bytes BE) | 16 zeros | y (48 bytes BE)]
fn g1_to_eip2537(point: &G1AffinePoint) -> [u8; 128] {
    let mut result = [0u8; 128];
    result[16..64].copy_from_slice(&fq_to_be48(&point.x));
    result[80..128].copy_from_slice(&fq_to_be48(&point.y));
    result
}

/// Converts a G2 affine point to the 256-byte EIP-2537 encoding.
/// Fp2 elements are encoded real-part-first (c0 before c1):
///   [16 zeros | x.c0 (48 BE) | 16 zeros | x.c1 (48 BE) | 16 zeros | y.c0 (48 BE) | 16 zeros | y.c1 (48 BE)]
fn g2_to_eip2537(point: &G2AffinePoint) -> [u8; 256] {
    let mut result = [0u8; 256];
    result[16..64].copy_from_slice(&fq_to_be48(&point.x.c0));
    result[80..128].copy_from_slice(&fq_to_be48(&point.x.c1));
    result[144..192].copy_from_slice(&fq_to_be48(&point.y.c0));
    result[208..256].copy_from_slice(&fq_to_be48(&point.y.c1));
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::AffineRepr;
    use ark_serialize::CanonicalDeserialize;

    // Parses a lowercase hex string into a Vec<u8>.
    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // --- G1 generator test vectors (from EIP-2537 spec) ---

    // Beacon-compressed G1 generator (48 bytes): first byte = 0x17 | 0x80 = 0x97 (compression flag,
    // sign bit clear because y < p/2), followed by the x coordinate.
    const G1_COMPRESSED_HEX: &str =
        "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac\
         586c55e83ff97a1aeffb3af00adb22c6bb";

    // Expected EIP-2537 G1 output (128 bytes): [16 zeros | x 48 BE | 16 zeros | y 48 BE]
    const G1_EIP2537_HEX: &str =
        "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0\
         fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6\
         bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8\
         ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

    // --- G2 generator test vectors (from EIP-2537 add_G2_bls.json) ---

    // Beacon-compressed G2 generator (96 bytes):
    //   bytes  0–47: x.c1 with flags (first byte = 0x13 | 0x80 = 0x93, sign bit clear)
    //   bytes 48–95: x.c0
    const G2_COMPRESSED_HEX: &str =
        "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f50\
         49334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51\
         051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";

    // Expected EIP-2537 G2 output (256 bytes):
    //   [16 zeros | x.c0 48 BE | 16 zeros | x.c1 48 BE | 16 zeros | y.c0 48 BE | 16 zeros | y.c1 48 BE]
    const G2_EIP2537_HEX: &str =
        "00000000000000000000000000000000024aa2b2f08f0a91260805272dc5105\
         1c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bd\
         b80000000000000000000000000000000013e02b6052719f607dacd3a088274f\
         65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b\
         7e000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e35\
         1aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b828\
         01000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b\
         99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";

    #[test]
    fn test_g1_generator_to_eip2537() {
        let point = G1AffinePoint::deserialize_compressed(
            from_hex(G1_COMPRESSED_HEX).as_slice()
        ).unwrap();
        assert_eq!(g1_to_eip2537(&point).as_ref(), from_hex(G1_EIP2537_HEX).as_slice());
    }

    #[test]
    fn test_g2_generator_to_eip2537() {
        let point = G2AffinePoint::deserialize_compressed(
            from_hex(G2_COMPRESSED_HEX).as_slice()
        ).unwrap();
        assert_eq!(g2_to_eip2537(&point).as_ref(), from_hex(G2_EIP2537_HEX).as_slice());
    }

    #[test]
    fn test_g1_generator_roundtrip_via_arkworks() {
        // Cross-check: verify the test vector matches what Arkworks reports for the generator.
        let gen = G1AffinePoint::generator();
        assert_eq!(g1_to_eip2537(&gen).as_ref(), from_hex(G1_EIP2537_HEX).as_slice());
    }

    #[test]
    fn test_g2_generator_roundtrip_via_arkworks() {
        let gen = G2AffinePoint::generator();
        assert_eq!(g2_to_eip2537(&gen).as_ref(), from_hex(G2_EIP2537_HEX).as_slice());
    }

    #[test]
    fn test_fq_to_be48_zero() {
        use ark_ff::Zero;
        let zero = Fq::zero();
        assert_eq!(fq_to_be48(&zero), [0u8; 48]);
    }
}

/// JNI for HintsLibraryBridge.decompressG1ToEip2537
/// Accepts a 48-byte compressed BLS12-381 G1 point and returns its 128-byte EIP-2537 encoding,
/// or null on error.
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_hints_HintsLibraryBridge_decompressG1ToEip2537Impl(
    env: JNIEnv,
    _instance: JObject,
    compressed_jarray: JByteArray,
) -> jbyteArray {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let compressed = match env.convert_byte_array(&compressed_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut(),
        };
        if compressed.len() != 48 {
            return std::ptr::null_mut();
        }
        let point = match G1AffinePoint::deserialize_compressed(&*compressed) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut(),
        };
        // deserialize_compressed uses Validate::Yes in ark-ec 0.4.2 and already checks this,
        // but we assert it explicitly so the requirement is visible and survives any future
        // change to deserialization flags. On BLS12-381, on-curve != in-subgroup.
        if !point.is_in_correct_subgroup_assuming_on_curve() {
            return std::ptr::null_mut();
        }
        jni_util::u8_vec_to_jbyte_array(&env, &g1_to_eip2537(&point).to_vec())
    })).unwrap_or_else(|_| std::ptr::null_mut())
}

/// JNI for HintsLibraryBridge.decompressG2ToEip2537
/// Accepts a 96-byte compressed BLS12-381 G2 point and returns its 256-byte EIP-2537 encoding,
/// or null on error.
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_hints_HintsLibraryBridge_decompressG2ToEip2537Impl(
    env: JNIEnv,
    _instance: JObject,
    compressed_jarray: JByteArray,
) -> jbyteArray {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let compressed = match env.convert_byte_array(&compressed_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut(),
        };
        if compressed.len() != 96 {
            return std::ptr::null_mut();
        }
        let point = match G2AffinePoint::deserialize_compressed(&*compressed) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut(),
        };
        // Same reasoning as G1: explicit check survives future Arkworks changes.
        // Explicit subgroup validation. For BLS12-381, being on the curve does not imply
        // membership in the correct prime-order subgroup. This prevents accepting invalid
        // small-subgroup points at the cryptographic boundary.
        if !point.is_in_correct_subgroup_assuming_on_curve() {
            return std::ptr::null_mut();
        }
        jni_util::u8_vec_to_jbyte_array(&env, &g2_to_eip2537(&point).to_vec())
    })).unwrap_or_else(|_| std::ptr::null_mut())
}