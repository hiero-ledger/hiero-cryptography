// SPDX-License-Identifier: Apache-2.0

use blst::{
    blst_core_verify_pk_in_g1, blst_p1, blst_p1_add_or_double, blst_p1_affine, blst_p1_affine_in_g1, blst_p1_cneg,
    blst_p1_deserialize, blst_p1_from_affine, blst_p1_is_inf, blst_p1_to_affine, blst_p2_affine, blst_p2_affine_in_g2,
    blst_p2_deserialize, BLST_ERROR,
};
use jni::JNIEnv;
use jni::objects::{JByteArray, JObject, JObjectArray};
use jni::sys::jboolean;
use crate::jni_util;

/// The domain separation tag of the ciphersuite Ethereum signs with: BLS12-381 with public keys in G1 and
/// signatures in G2, messages hashed to G2 per RFC 9380, and the proof-of-possession scheme.
const ETHEREUM_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// The length of a base field element, big-endian.
const FP_LENGTH_BYTES: usize = 48;
/// EIP-2537 pads every base field element to 64 bytes with 16 leading zero bytes.
const EIP2537_FP_PADDING_LENGTH_BYTES: usize = 16;
const EIP2537_FP_LENGTH_BYTES: usize = EIP2537_FP_PADDING_LENGTH_BYTES + FP_LENGTH_BYTES;

/// The compression, infinity and sign flags in the first byte of a ZCash serialization.
const ZCASH_FLAGS_MASK: u8 = 0xe0;

/// JNI for EthereumBlsBridge.validateG1Eip2537PublicKeys
/// Accepts an array of 128-byte EIP-2537 G1 public keys and returns true if it's not empty and every public key is
/// valid, or false otherwise and on error.
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_hints_EthereumBlsBridge_validateG1Eip2537PublicKeysImpl(
    mut env: JNIEnv,
    _instance: JObject,
    public_keys_jarray: JObjectArray,
) -> jboolean {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let public_keys = match jni_util::jbyte_arrays_to_u8_vecs(&mut env, &public_keys_jarray) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false),
        };
        jboolean::from(validate_g1_eip2537_public_keys(&public_keys))
    })).unwrap_or_else(|_| jboolean::from(false))
}

/// Returns true if the list is not empty and every public key is valid in the EIP-2537 encoding.
fn validate_g1_eip2537_public_keys(public_keys: &[Vec<u8>]) -> bool {
    !public_keys.is_empty() && public_keys.iter().all(|public_key| g1_from_eip2537(public_key).is_some())
}

/// JNI for EthereumBlsBridge.verifySyncAggregate
/// Accepts the 128-byte EIP-2537 aggregate public key of a committee, the 128-byte EIP-2537 public keys of the
/// members that did not sign, a message and a 256-byte EIP-2537 signature. Returns true if the signature verifies
/// under the aggregate public key of the members that signed, or false otherwise and on error.
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_hints_EthereumBlsBridge_verifySyncAggregateImpl(
    mut env: JNIEnv,
    _instance: JObject,
    aggregate_public_key_jarray: JByteArray,
    non_signer_public_keys_jarray: JObjectArray,
    message_jarray: JByteArray,
    signature_jarray: JByteArray,
) -> jboolean {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let aggregate_public_key = match env.convert_byte_array(&aggregate_public_key_jarray) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false),
        };
        let non_signer_public_keys = match jni_util::jbyte_arrays_to_u8_vecs(&mut env, &non_signer_public_keys_jarray) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false),
        };
        let message = match env.convert_byte_array(&message_jarray) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false),
        };
        let signature = match env.convert_byte_array(&signature_jarray) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false),
        };
        jboolean::from(verify_sync_aggregate(&aggregate_public_key, &non_signer_public_keys, &message, &signature))
    })).unwrap_or_else(|_| jboolean::from(false))
}

/// Recovers the aggregate public key of the signers as the committee's aggregate public key minus the public keys
/// of the members that did not sign, then verifies the signature under it. All points use the EIP-2537 encoding.
fn verify_sync_aggregate(
    aggregate_public_key: &[u8],
    non_signer_public_keys: &[Vec<u8>],
    message: &[u8],
    signature: &[u8],
) -> bool {
    let aggregate_public_key = match g1_from_eip2537(aggregate_public_key) {
        Some(val) => val,
        None => return false,
    };
    let signature = match g2_from_eip2537(signature) {
        Some(val) => val,
        None => return false,
    };
    let mut signers = blst_p1::default();
    unsafe { blst_p1_from_affine(&mut signers, &aggregate_public_key) };
    for encoded in non_signer_public_keys {
        let non_signer = match g1_from_eip2537(encoded) {
            Some(val) => val,
            None => return false,
        };
        let mut negated = blst_p1::default();
        let previous = signers;
        unsafe {
            blst_p1_from_affine(&mut negated, &non_signer);
            blst_p1_cneg(&mut negated, true);
            blst_p1_add_or_double(&mut signers, &previous, &negated);
        }
    }
    verify_signers(&signers, message, &signature)
}

/// Decodes a 128-byte EIP-2537 G1 point, and accepts only a valid public key per the KeyValidate procedure of
/// the BLS signature spec: a point on the curve, in the prime-order subgroup, and not the identity.
fn g1_from_eip2537(encoded: &[u8]) -> Option<blst_p1_affine> {
    // Both encodings order the coordinates x, y.
    let serialized = eip2537_to_zcash(encoded, &[0, 1])?;
    let mut point = blst_p1_affine::default();
    if unsafe { blst_p1_deserialize(&mut point, serialized.as_ptr()) } != BLST_ERROR::BLST_SUCCESS
        || !unsafe { blst_p1_affine_in_g1(&point) } {
        return None;
    }
    Some(point)
}

/// Decodes a 256-byte EIP-2537 G2 point, and accepts only a point on the curve, in the prime-order subgroup, and
/// not the identity.
fn g2_from_eip2537(encoded: &[u8]) -> Option<blst_p2_affine> {
    // EIP-2537 writes each Fp2 coordinate c0 first (x.c0, x.c1, y.c0, y.c1); ZCash writes c1 first.
    let serialized = eip2537_to_zcash(encoded, &[1, 0, 3, 2])?;
    let mut point = blst_p2_affine::default();
    if unsafe { blst_p2_deserialize(&mut point, serialized.as_ptr()) } != BLST_ERROR::BLST_SUCCESS
        || !unsafe { blst_p2_affine_in_g2(&point) } {
        return None;
    }
    Some(point)
}

/// Converts an EIP-2537 point into the uncompressed ZCash serialization that blst deserializes: strips the zero
/// padding off every base field element, and writes input element `order[i]` as output element `i`.
/// Returns None if the length is wrong, a padding byte is not zero, an element is too large to be below the field
/// modulus, or the point is the identity. EIP-2537 encodes the identity as all zeros, which blst would reject as a
/// point off the curve; it's rejected explicitly here because no caller accepts it.
fn eip2537_to_zcash(encoded: &[u8], order: &[usize]) -> Option<Vec<u8>> {
    if encoded.len() != order.len() * EIP2537_FP_LENGTH_BYTES || encoded.iter().all(|&byte| byte == 0) {
        return None;
    }
    let mut serialized = Vec::with_capacity(order.len() * FP_LENGTH_BYTES);
    for &element in order {
        let padded = &encoded[element * EIP2537_FP_LENGTH_BYTES..(element + 1) * EIP2537_FP_LENGTH_BYTES];
        let (padding, fp) = padded.split_at(EIP2537_FP_PADDING_LENGTH_BYTES);
        if padding.iter().any(|&byte| byte != 0) {
            return None;
        }
        serialized.extend_from_slice(fp);
    }
    // The field modulus has 381 bits, so the top three bits of a canonical element are zero. blst checks that
    // every element is below the modulus, except that it reads these bits of the first element as flags: a set
    // compression flag, for one, would make it decode only the first half as a compressed point.
    if serialized[0] & ZCASH_FLAGS_MASK != 0 {
        return None;
    }
    Some(serialized)
}

/// Checks the pairing equation e(signers, H(message)) == e(g1, signature), where H hashes to G2 with the
/// Ethereum DST. Rejects an identity aggregate public key, e.g. one where the non-signers cancel out the whole
/// committee: it would satisfy the equation for the identity signature, whatever the message.
fn verify_signers(signers: &blst_p1, message: &[u8], signature: &blst_p2_affine) -> bool {
    if unsafe { blst_p1_is_inf(signers) } {
        return false;
    }
    let mut signers_affine = blst_p1_affine::default();
    unsafe {
        blst_p1_to_affine(&mut signers_affine, signers);
        blst_core_verify_pk_in_g1(
            &signers_affine,
            signature,
            true, // hash to the curve, as the RO in the DST says, rather than encode to it
            message.as_ptr(),
            message.len(),
            ETHEREUM_DST.as_ptr(),
            ETHEREUM_DST.len(),
            std::ptr::null(),
            0,
        ) == BLST_ERROR::BLST_SUCCESS
    }
}
