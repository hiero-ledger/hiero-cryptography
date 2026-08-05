// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use jni::JNIEnv;
use jni::objects::{JByteArray, JIntArray, JLongArray, JObject, JObjectArray, JValue};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jobject, jsize};
use crate::hints::{AggregationKey, ExtendedPublicKey, HinTS, PartialSignature, SecretKey, ThresholdSignature, VerificationKey, Weight, CRS, F};
use crate::jni_cache::JNICache;
use crate::jni_util;

// Caches for some "static" values to save time on parsing them from bytes.
// Java applications can reset the caches by calling HintsLibraryBridge.resetCache().
static CRS_CACHE: JNICache<CRS> = JNICache::new(jni_util::deserialize_jbyte_array);
static AGGREGATION_KEY_CACHE: JNICache<AggregationKey> = JNICache::new(jni_util::deserialize_jbyte_array);

/// JNI for HintsLibraryBridge.generateSecretKey
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_hints_HintsLibraryBridge_generateSecretKey(
    env: JNIEnv,
    _instance: JObject,
    random_jarray: JByteArray,
) -> jbyteArray {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let random_arr = match jni_util::build_entropy_array(&env, &random_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let secret_key = match HinTS::keygen(random_arr) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut(),
        };
        match jni_util::serialize_object(&env, &secret_key) {
            Ok(val) => val,
            Err(_) => std::ptr::null_mut()
        }
    })).unwrap_or_else(|_| std::ptr::null_mut())
}

/// JNI for HintsLibraryBridge.computeHints
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_hints_HintsLibraryBridge_computeHintsImpl(
    env: JNIEnv,
    _instance: JObject,
    crs_jarray: JByteArray,
    secret_key_jarray: JByteArray,
    party_id: jint,
    n: jint,
) -> jbyteArray {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let crs: &CRS = match CRS_CACHE.get(&env, &crs_jarray) {
            Ok(val) => &(val.clone()),
            Err(_) => return std::ptr::null_mut()
        };

        let secret_key: SecretKey = match jni_util::deserialize_jbyte_array(&env, &secret_key_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let hint = match HinTS::hint_gen(&crs, n as usize, party_id as usize, &secret_key) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };
        match jni_util::serialize_object(&env, &hint) {
            Ok(val) => val,
            Err(_) => std::ptr::null_mut()
        }
    })).unwrap_or_else(|_| std::ptr::null_mut())
}

/// JNI for HintsLibraryBridge.validateHintsKey
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_hints_HintsLibraryBridge_validateHintsKeyImpl(
    env: JNIEnv,
    _instance: JObject,
    crs_jarray: JByteArray,
    hints_jarray: JByteArray,
    party_id: jint,
    n: jint,
) -> jboolean {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let crs: &CRS = match CRS_CACHE.get(&env, &crs_jarray) {
            Ok(val) => &(val.clone()),
            Err(_) => return jboolean::from(false)
        };

        let hints: ExtendedPublicKey = match jni_util::deserialize_jbyte_array(&env, &hints_jarray) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false)
        };

        jboolean::from(match HinTS::verify_hint(&crs, n as usize, party_id as usize, &hints) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false)
        })
    })).unwrap_or_else(|_| jboolean::from(false))
}

/// JNI for HintsLibraryBridge.preprocess
#[no_mangle]
pub unsafe extern "system" fn Java_com_hedera_cryptography_hints_HintsLibraryBridge_preprocessImpl(
    mut env: JNIEnv,
    _instance: JObject,
    crs_jarray: JByteArray,
    parties_jarray: JIntArray,
    hints_jarray: JObjectArray,
    weights_jarray: JLongArray,
    n: jint,
) -> jobject {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let crs: &CRS = match CRS_CACHE.get(&env, &crs_jarray) {
            Ok(val) => &(val.clone()),
            Err(_) => return std::ptr::null_mut()
        };

        // ------------------------------------------------------------------------
        // build HashMap<usize, (Weight, ExtendedPublicKey)>
        let num_of_keys = match env.get_array_length(&parties_jarray) {
            Ok(len) => len,
            Err(_) => return std::ptr::null_mut()
        };
        let mut keys :Vec<jint> = vec![0; num_of_keys as usize];
        match env.get_int_array_region(parties_jarray, 0, keys.as_mut_slice()) {
            Ok(()) => {},
            Err(_) => return std::ptr::null_mut()
        };

        let mut weights :Vec<jlong> = vec![0; num_of_keys as usize];
        match env.get_long_array_region(weights_jarray, 0, weights.as_mut_slice()) {
            Ok(()) => {},
            Err(_) => return std::ptr::null_mut()
        };

        let mut hints_array:Vec<ExtendedPublicKey> = Vec::with_capacity(num_of_keys as usize);
        for i in 0..num_of_keys as usize {
            let jobj = match env.get_object_array_element(&hints_jarray, i as jsize) {
                Ok(val) => val,
                Err(_) => return std::ptr::null_mut()
            };

            let hints: ExtendedPublicKey = match jni_util::deserialize_jbyte_array(&env, &JByteArray::from(jobj)) {
                Ok(val) => val,
                Err(_) => return std::ptr::null_mut()
            };

            hints_array.push(hints);
        }

        let mut signer_info: HashMap<usize, (Weight, ExtendedPublicKey)> = HashMap::with_capacity(num_of_keys as usize);
        for i in 0..num_of_keys as usize {
            signer_info.insert(keys[i] as usize, (Weight::from(weights[i] as i64), hints_array[i].clone()));
        }
        // finished building the map
        // ------------------------------------------------------------------------

        let (vk, ak) = match HinTS::preprocess(n as usize, &crs, &signer_info) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let serialized_vk = match jni_util::serialize_object(&env, &vk) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };
        let serialized_ak = match jni_util::serialize_object(&env, &ak) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let keys_clz = match env.find_class("com/hedera/cryptography/hints/AggregationAndVerificationKeys") {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };
        let keys_obj = match env.new_object(keys_clz, "([B[B)V", &[JValue::from(&JObject::from_raw(serialized_vk)), JValue::from(&JObject::from_raw(serialized_ak))]) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        keys_obj.into_raw()
    })).unwrap_or_else(|_| std::ptr::null_mut())
}

/// JNI for HintsLibraryBridge.signBls
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_hints_HintsLibraryBridge_signBlsImpl(
    env: JNIEnv,
    _instance: JObject,
    message_jarray: JByteArray,
    secret_key_jarray: JByteArray,
) -> jbyteArray {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let message = match env.convert_byte_array(&message_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let secret_key: SecretKey = match jni_util::deserialize_jbyte_array(&env, &secret_key_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let signature = match HinTS::sign(&message, &secret_key) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };
        match jni_util::serialize_object(&env, &signature) {
            Ok(val) => val,
            Err(_) => std::ptr::null_mut()
        }
    })).unwrap_or_else(|_| std::ptr::null_mut())
}

/// JNI for HintsLibraryBridge.verifyBls
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_hints_HintsLibraryBridge_verifyBlsImpl(
    env: JNIEnv,
    _instance: JObject,
    signature_jarray: JByteArray,
    message_jarray: JByteArray,
    aggregation_key_jarray: JByteArray,
    party_id: jint
) -> jboolean {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let message = match env.convert_byte_array(&message_jarray) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false)
        };

        let aggregation_key: &AggregationKey = match AGGREGATION_KEY_CACHE.get(&env, &aggregation_key_jarray) {
            Ok(val) => &(val.clone()),
            Err(_) => return jboolean::from(false)
        };

        let signature: PartialSignature = match jni_util::deserialize_jbyte_array(&env, &signature_jarray) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false)
        };

        jboolean::from(match HinTS::partial_verify(&message, &aggregation_key, party_id as usize, &signature) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false)
        })
    })).unwrap_or_else(|_| jboolean::from(false))
}

/// JNI for HintsLibraryBridge.verifyBlsBatch
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_hints_HintsLibraryBridge_verifyBlsBatchImpl(
    mut env: JNIEnv,
    _instance: JObject,
    message_jarray: JByteArray,
    aggregation_key_jarray: JByteArray,
    parties_jarray: JIntArray,
    partial_signatures_jarray: JObjectArray
) -> jboolean {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let message = match env.convert_byte_array(&message_jarray) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false)
        };

        let aggregation_key: &AggregationKey = match AGGREGATION_KEY_CACHE.get(&env, &aggregation_key_jarray) {
            Ok(val) => &(val.clone()),
            Err(_) => return jboolean::from(false)
        };

        let num_of_keys = match env.get_array_length(&parties_jarray) {
            Ok(len) => len,
            Err(_) => return jboolean::from(false)
        };
        let mut keys :Vec<jint> = vec![0; num_of_keys as usize];
        match env.get_int_array_region(parties_jarray, 0, keys.as_mut_slice()) {
            Ok(()) => {},
            Err(_) => return jboolean::from(false)
        };
        let keys_usize: Vec<usize> = keys.iter().map(|&x| x as usize).collect();

        let mut partial_signatures_array:Vec<PartialSignature> = Vec::with_capacity(num_of_keys as usize);
        for i in 0..num_of_keys as usize {
            let jobj = match env.get_object_array_element(&partial_signatures_jarray, i as jsize) {
                Ok(val) => val,
                Err(_) => return jboolean::from(false)
            };

            let partial_signature: PartialSignature = match jni_util::deserialize_jbyte_array(&env, &JByteArray::from(jobj)) {
                Ok(val) => val,
                Err(_) => return jboolean::from(false)
            };

            partial_signatures_array.push(partial_signature);
        }

        jboolean::from(match HinTS::partial_verify_batch(&message, &aggregation_key, &keys_usize, &partial_signatures_array) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false)
        })
    })).unwrap_or_else(|_| jboolean::from(false))
}

/// JNI for HintsLibraryBridge.aggregateSignatures
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_hints_HintsLibraryBridge_aggregateSignaturesImpl(
    mut env: JNIEnv,
    _instance: JObject,
    crs_jarray: JByteArray,
    aggregation_key_jarray: JByteArray,
    verification_key_jarray: JByteArray,
    parties_jarray: JIntArray,
    partial_signatures_jarray: JObjectArray,
) -> jbyteArray {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let crs: &CRS = match CRS_CACHE.get(&env, &crs_jarray) {
            Ok(val) => &(val.clone()),
            Err(_) => return std::ptr::null_mut()
        };

        let aggregation_key: &AggregationKey = match AGGREGATION_KEY_CACHE.get(&env, &aggregation_key_jarray) {
            Ok(val) => &(val.clone()),
            Err(_) => return std::ptr::null_mut()
        };

        let verification_key: VerificationKey = match jni_util::deserialize_jbyte_array(&env, &verification_key_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        // ------------------------------------------------------------------------
        // build HashMap<usize, PartialSignature>
        let num_of_keys = match env.get_array_length(&parties_jarray) {
            Ok(len) => len,
            Err(_) => return std::ptr::null_mut()
        };
        let mut keys :Vec<jint> = vec![0; num_of_keys as usize];
        match env.get_int_array_region(parties_jarray, 0, keys.as_mut_slice()) {
            Ok(()) => {},
            Err(_) => return std::ptr::null_mut()
        };

        let mut partial_signatures_array:Vec<PartialSignature> = Vec::with_capacity(num_of_keys as usize);
        for i in 0..num_of_keys as usize {
            let jobj = match env.get_object_array_element(&partial_signatures_jarray, i as jsize) {
                Ok(val) => val,
                Err(_) => return std::ptr::null_mut()
            };

            let partial_signature: PartialSignature = match jni_util::deserialize_jbyte_array(&env, &JByteArray::from(jobj)) {
                Ok(val) => val,
                Err(_) => return std::ptr::null_mut()
            };

            partial_signatures_array.push(partial_signature);
        }

        let mut partial_signatures: HashMap<usize, PartialSignature> = HashMap::with_capacity(num_of_keys as usize);
        for i in 0..num_of_keys as usize {
            partial_signatures.insert(keys[i] as usize, partial_signatures_array[i].clone());
        }
        // finished building the map
        // ------------------------------------------------------------------------

        let threshold_signature = match HinTS::aggregate(&crs, &aggregation_key, &verification_key, &partial_signatures) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };
        match jni_util::serialize_object(&env, &threshold_signature) {
            Ok(val) => val,
            Err(_) => std::ptr::null_mut()
        }
    })).unwrap_or_else(|_| std::ptr::null_mut())
}

/// JNI for HintsLibraryBridge.verifyAggregate
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_hints_HintsLibraryBridge_verifyAggregateImpl(
    env: JNIEnv,
    _instance: JObject,
    signature_jarray: JByteArray,
    message_jarray: JByteArray,
    verification_key_jarray: JByteArray,
    threshold_numerator: jlong,
    threshold_denominator: jlong,
) -> jboolean {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let signature: ThresholdSignature = match jni_util::deserialize_jbyte_array(&env, &signature_jarray) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false)
        };

        let message = match env.convert_byte_array(&message_jarray) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false)
        };

        let verification_key: VerificationKey = match jni_util::deserialize_jbyte_array(&env, &verification_key_jarray) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false)
        };

        jboolean::from(match HinTS::verify(&message, &verification_key, &signature, (F::from(threshold_numerator), F::from(threshold_denominator))) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false)
        })
    })).unwrap_or_else(|_| jboolean::from(false))
}

/// JNI for HintsLibraryBridge.resetCache
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_hints_HintsLibraryBridge_resetCache(
    _env: JNIEnv,
) {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        CRS_CACHE.reset();
        AGGREGATION_KEY_CACHE.reset();
    })).unwrap_or_else(|_| ())
}
