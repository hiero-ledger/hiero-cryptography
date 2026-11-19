// SPDX-License-Identifier: Apache-2.0

use jni::objects::{JByteArray, JObject};
use jni::sys::{jbyteArray, jboolean, jshort};
use jni::JNIEnv;
use crate::setup::{ContributionProof, PowersOfTauProtocol};
use crate::hints::{serialize, CRS};
use crate::jni_util;

/// JNI function to create a new CRS object
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `signers_num` the CRS degree, i.e. the number of signers plus 1
/// # Returns
/// *   a byte array with a serialized CRS object, or null on error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_hints_HintsLibraryBridge_initCRSImpl(
    env: JNIEnv,
    _instance: JObject,
    signers_num: jshort,
) -> jbyteArray {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let crs = PowersOfTauProtocol::init(signers_num as usize);
        match jni_util::serialize_object(&env, &crs) {
            Ok(val) => val,
            Err(_) => std::ptr::null_mut()
        }
    })).unwrap_or_else(|_| std::ptr::null_mut())
}

/// JNI function to update a CRS object
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `prev_crs_array` the previous CRS
/// * `random_array` the randomness
/// # Returns
/// *   a byte array with a serialized next CRS object and its contribution proof, or null on error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_hints_HintsLibraryBridge_updateCRSImpl(
    env: JNIEnv,
    _instance: JObject,
    prev_crs_array: JByteArray,
    random_array: JByteArray,
) -> jbyteArray {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let prev_crs: CRS = match jni_util::deserialize_jbyte_array(&env, &prev_crs_array) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let random_arr = match jni_util::build_entropy_array(&env, &random_array) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let (crs, contribution_proof) = match PowersOfTauProtocol::contribute(&prev_crs, random_arr) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let serialized_crs = match serialize(&crs) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };
        let serialized_contribution_proof = match serialize(&contribution_proof) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        jni_util::two_u8_vec_to_jbyte_array(&env, &serialized_crs, &serialized_contribution_proof)
    })).unwrap_or_else(|_| std::ptr::null_mut())
}

/// JNI function to verify the next CRS object with its ContributionProof
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `prev_crs_array` the previous CRS
/// * `next_crs_array` the next CRS
/// * `contribution_proof_array` the contribution proof
/// # Returns
/// *   true if verified, false if unverified or on error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_hints_HintsLibraryBridge_verifyCRSImpl(
    env: JNIEnv,
    _instance: JObject,
    prev_crs_array: JByteArray,
    next_crs_array: JByteArray,
    contribution_proof_array: JByteArray,
) -> jboolean {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let prev_crs :CRS = match jni_util::deserialize_jbyte_array(&env, &prev_crs_array) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false)
        };

        let next_crs :CRS = match jni_util::deserialize_jbyte_array(&env, &next_crs_array) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false)
        };

        let contribution_proof: ContributionProof = match jni_util::deserialize_jbyte_array(&env, &contribution_proof_array) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false)
        };

        jboolean::from(PowersOfTauProtocol::verify_contribution(&prev_crs, &next_crs, &contribution_proof))
    })).unwrap_or_else(|_| jboolean::from(false))
}

/// JNI for HintsLibraryBridge.pruneCRSImpl
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_hints_HintsLibraryBridge_pruneCRSImpl(
    env: JNIEnv,
    _instance: JObject,
    prev_crs_array: JByteArray,
    signers_num: jshort,
) -> jbyteArray {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let prev_crs :CRS = match jni_util::deserialize_jbyte_array(&env, &prev_crs_array) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let crs :CRS = match PowersOfTauProtocol::prune_crs(&prev_crs, signers_num as usize) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        match jni_util::serialize_object(&env, &crs) {
            Ok(val) => val,
            Err(_) => std::ptr::null_mut()
        }
    })).unwrap_or_else(|_| std::ptr::null_mut())
}
