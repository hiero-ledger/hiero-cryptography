// SPDX-License-Identifier: Apache-2.0

use jni::objects::{JBooleanArray, JByteArray, JObject, JObjectArray};
use jni::sys::{jboolean, jbyteArray, jsize};
use jni::JNIEnv;
use crate::bls::Bls;
use crate::jni_util;

/// JNI for BlsLibraryBridge.verifySignature
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `signature_jarray` the serialized signature
/// * `message_jarray` the signed message
/// * `public_key_jarray` the serialized public key of the signer
/// # Returns
/// *   true if the signature verifies, false if it does not or on error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_hints_BlsLibraryBridge_verifySignatureImpl(
    env: JNIEnv,
    _instance: JObject,
    signature_jarray: JByteArray,
    message_jarray: JByteArray,
    public_key_jarray: JByteArray,
) -> jboolean {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let signature = match env.convert_byte_array(&signature_jarray) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false)
        };

        let message = match env.convert_byte_array(&message_jarray) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false)
        };

        let public_key = match env.convert_byte_array(&public_key_jarray) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false)
        };

        jboolean::from(match Bls::verify(&message, &public_key, &signature) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false)
        })
    })).unwrap_or_else(|_| jboolean::from(false))
}

/// JNI for BlsLibraryBridge.aggregatePublicKeys
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `public_keys_jarray` the serialized public keys, one per party
/// * `bitvector_jarray` the flags marking which public keys take part, of equal length
/// # Returns
/// *   a byte array with the serialized aggregate public key, or null on error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_hints_BlsLibraryBridge_aggregatePublicKeysImpl(
    mut env: JNIEnv,
    _instance: JObject,
    public_keys_jarray: JObjectArray,
    bitvector_jarray: JBooleanArray,
) -> jbyteArray {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let num_of_keys = match env.get_array_length(&public_keys_jarray) {
            Ok(len) => len,
            Err(_) => return std::ptr::null_mut()
        };

        // the two arrays model a map from party to participation, so they must agree in size
        match env.get_array_length(&bitvector_jarray) {
            Ok(len) if len == num_of_keys => {},
            _ => return std::ptr::null_mut()
        };

        let mut bits :Vec<jboolean> = vec![0; num_of_keys as usize];
        match env.get_boolean_array_region(&bitvector_jarray, 0, bits.as_mut_slice()) {
            Ok(()) => {},
            Err(_) => return std::ptr::null_mut()
        };
        let bitvector: Vec<bool> = bits.iter().map(|&bit| bit != 0).collect();

        // only the selected entries are read, so an unselected entry may be null or garbage
        let mut public_keys :Vec<Vec<u8>> = Vec::with_capacity(num_of_keys as usize);
        for i in 0..num_of_keys as usize {
            if !bitvector[i] {
                public_keys.push(Vec::new());
                continue;
            }

            let jobj = match env.get_object_array_element(&public_keys_jarray, i as jsize) {
                Ok(val) => val,
                Err(_) => return std::ptr::null_mut()
            };

            let public_key = match env.convert_byte_array(&JByteArray::from(jobj)) {
                Ok(val) => val,
                Err(_) => return std::ptr::null_mut()
            };

            public_keys.push(public_key);
        }

        let aggregate_public_key = match Bls::aggregate_public_keys(&public_keys, &bitvector) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        jni_util::u8_vec_to_jbyte_array(&env, &aggregate_public_key)
    })).unwrap_or_else(|_| std::ptr::null_mut())
}
