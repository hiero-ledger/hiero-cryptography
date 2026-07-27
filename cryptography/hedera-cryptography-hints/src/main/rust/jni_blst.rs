// SPDX-License-Identifier: Apache-2.0

use blst::{ blst_p1_uncompress, blst_p1_affine, BLST_ERROR, blst_p1_affine_in_g1, blst_fp, blst_bendian_from_fp, blst_p2_affine, blst_p2_uncompress, blst_p2_affine_in_g2 };
use jni::JNIEnv;
use jni::objects::{JByteArray, JObject};
use jni::sys::jbyteArray;
use crate::jni_util;

/// Returns the big-endian byte representation of a blst_fp field element.
fn fq_to_be48(fq: &blst_fp) -> [u8; 48] {
    let mut result = [0u8; 48];
    unsafe { blst_bendian_from_fp(result.as_mut_ptr(), fq); };
    result
}

/// Converts a G1 affine point to the 128-byte EIP-2537 encoding:
///   [16 zeros | x (48 bytes BE) | 16 zeros | y (48 bytes BE)]
fn g1_to_eip2537(point: &blst_p1_affine) -> [u8; 128] {
    let mut result = [0u8; 128];
    result[16..64].copy_from_slice(&fq_to_be48(&point.x));
    result[80..128].copy_from_slice(&fq_to_be48(&point.y));
    result
}

/// Converts a G2 affine point to the 256-byte EIP-2537 encoding.
/// Fp2 elements are encoded real-part-first (c0 before c1):
///   [16 zeros | x.c0 (48 BE) | 16 zeros | x.c1 (48 BE) | 16 zeros | y.c0 (48 BE) | 16 zeros | y.c1 (48 BE)]
fn g2_to_eip2537(point: &blst_p2_affine) -> [u8; 256] {
    let mut result = [0u8; 256];
    result[16..64].copy_from_slice(&fq_to_be48(&point.x.fp[0]));
    result[80..128].copy_from_slice(&fq_to_be48(&point.x.fp[1]));
    result[144..192].copy_from_slice(&fq_to_be48(&point.y.fp[0]));
    result[208..256].copy_from_slice(&fq_to_be48(&point.y.fp[1]));
    result
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
        let mut point = blst_p1_affine::default();
        if unsafe { blst_p1_uncompress(&mut point, compressed.as_ptr()) } != BLST_ERROR::BLST_SUCCESS {
            return std::ptr::null_mut();
        }
        if !unsafe { blst_p1_affine_in_g1(&point) } {
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
        let mut point = blst_p2_affine::default();

        if unsafe { blst_p2_uncompress(&mut point, compressed.as_ptr()) } != BLST_ERROR::BLST_SUCCESS {
            return std::ptr::null_mut();
        }
        if !unsafe { blst_p2_affine_in_g2(&point) } {
            return std::ptr::null_mut();
        }
        jni_util::u8_vec_to_jbyte_array(&env, &g2_to_eip2537(&point).to_vec())
    })).unwrap_or_else(|_| std::ptr::null_mut())
}
