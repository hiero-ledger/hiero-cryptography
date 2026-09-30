// SPDX-License-Identifier: Apache-2.0

use jni::sys::{jbyteArray, jboolean, jobject, jint};
use jni::{JNIEnv};
use jni::objects::{JByteArray, JObject, JObjectArray, JValue, JLongArray, JBooleanArray, JString, JClass};
use std::sync::OnceLock;
//use nova_snark::frontend::Assignment;

use crate::{jni_util, WRAPS, SigningProtocolPhase, ENTROPY_SIZE, SigningProtocolMessage, SigningProtocolObject, SchnorrMultiSignature, AddressBook, AddressBookHash, SchnorrSecretKey, E2, HintsVKHash, PublicParams, CompressedVerifyingKey};
use crate::jni_util::deserialize_from_jbyte_array;

//const SECRET_KEY_LENGTH: usize = 32;

/// PublicParams are baked into the library JAR and are constant.
/// The Option would only be empty if the loading failed.
static PUBLIC_PARAMS: OnceLock<Option<PublicParams>> = OnceLock::new();

/// The compressed verifying key is derived from the PublicParams, and hence is constant as well.
static COMPRESSED_VERIFYING_KEY: OnceLock<Option<CompressedVerifyingKey>> = OnceLock::new();

/// JNI for WRAPSLibraryBridge.loadPublicParams
#[no_mangle]
pub unsafe extern "system" fn Java_com_hedera_cryptography_wraps_WRAPSLibraryBridge_loadPublicParams(
    mut env: JNIEnv,
    _clz: JClass,
    path: JString,
) -> jboolean {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if path.is_null() {
            return jboolean::from(false);
        }
        let java_str = match env.get_string(&path) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false)
        };
        let rust_str: &str = match java_str.to_str() {
            Ok(val) => val,
            Err(_) => return jboolean::from(false)
        };
        let rust_path = std::path::PathBuf::from(rust_str);

        let option_params = PUBLIC_PARAMS.get_or_init(|| {
            match WRAPS::load_public_params(&rust_path) {
                Ok(val) => Some(val),
                Err(_e) => None
            }
        });

        jboolean::from(option_params.is_some())
    })).unwrap_or_else(|_| jboolean::from(false))
}

/// JNI for WRAPSLibraryBridge.generateSchnorrKeysImpl
#[no_mangle]
pub unsafe extern "system" fn Java_com_hedera_cryptography_wraps_WRAPSLibraryBridge_generateSchnorrKeysImpl(
    mut env: JNIEnv,
    _instance: JObject,
    random_jarray: JByteArray,
) -> jobject {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let random_arr = match jni_util::build_entropy_array(&env, &random_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let (private_key, public_key) = WRAPS::keygen(random_arr);

        let serialized_private_key = match jni_util::serialize_to_jbyte_array(&env, &private_key) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };
        let serialized_public_key = match jni_util::serialize_to_jbyte_array(&env, &public_key) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let keys_clz = match env.find_class("com/hedera/cryptography/wraps/SchnorrKeys") {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };
        let keys_obj = match env.new_object(keys_clz, "([B[B)V", &[JValue::from(&JObject::from_raw(serialized_private_key)), JValue::from(&JObject::from_raw(serialized_public_key))]) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        keys_obj.into_raw()
    })).unwrap_or_else(|_| std::ptr::null_mut())
}

/// JNI for WRAPSLibraryBridge.provideSentinelPublicKey
#[no_mangle]
pub unsafe extern "system" fn Java_com_hedera_cryptography_wraps_WRAPSLibraryBridge_provideSentinelPublicKey(
    env: JNIEnv,
    _instance: JObject,
) -> jbyteArray {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let public_key = WRAPS::sentinel_keygen();
        jni_util::serialize_to_jbyte_array(&env, &public_key).unwrap_or_else(|_| std::ptr::null_mut())
    })).unwrap_or_else(|_| std::ptr::null_mut())
}

/// JNI for WRAPSLibraryBridge.runSigningProtocolPhaseImpl
#[no_mangle]
pub unsafe extern "system" fn Java_com_hedera_cryptography_wraps_WRAPSLibraryBridge_runSigningProtocolPhaseImpl(
    mut env: JNIEnv,
    _instance: JObject,
    phase_ordinal: jint,
    random_jarray: JByteArray,
    message_jarray: JByteArray,
    schnorr_private_key_jarray: JByteArray,
    schnorr_public_keys_jarray: JObjectArray,
    weights_jarray: JLongArray,
    node_ids_jarray: JLongArray,
    signers_jarray: JBooleanArray,
    round1messages_jarray: JObjectArray,
    round2messages_jarray: JObjectArray,
    round3messages_jarray: JObjectArray,
) -> jbyteArray {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let phase = match phase_ordinal {
            0 => SigningProtocolPhase::R1,
            1 => SigningProtocolPhase::R2,
            2 => SigningProtocolPhase::R3,
            3 => SigningProtocolPhase::Aggregate,
            _ => return std::ptr::null_mut()
        };

        let random_arr: Option<[u8; ENTROPY_SIZE]> = if random_jarray.is_null() { None } else {
            match jni_util::build_entropy_array(&env, &random_jarray) {
                Ok(val) => Some(val),
                Err(_) => return std::ptr::null_mut()
            }
        };

        let message = match env.convert_byte_array(&message_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let signing_key: Option<SchnorrSecretKey<E2>> = if schnorr_private_key_jarray.is_null() { None } else {
            match deserialize_from_jbyte_array(&env, &schnorr_private_key_jarray) {
                Ok(val) => Some(val),
                Err(_) => return std::ptr::null_mut()
            }
        };

        let ab: AddressBook<E2> = match jni_util::build_address_book(&mut env, schnorr_public_keys_jarray, weights_jarray, node_ids_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };
        let signers: Vec<bool> = match jni_util::jboolean_array_to_vec(&env, signers_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };
        let round1messages: Vec<SigningProtocolMessage> = match jni_util::build_vector(&mut env, &round1messages_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };
        let round2messages: Vec<SigningProtocolMessage> = match jni_util::build_vector(&mut env, &round2messages_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };
        let round3messages: Vec<SigningProtocolMessage> = match jni_util::build_vector(&mut env, &round3messages_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let obj: SigningProtocolObject<E2> = match WRAPS::signing_protocol(phase, random_arr, message, signing_key.as_ref(), &ab, &signers, &round1messages, &round2messages, &round3messages) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        match obj {
            SigningProtocolObject::ProtocolMessage(msg_encoded) => jni_util::serialize_to_jbyte_array(&env, &msg_encoded),
            SigningProtocolObject::ProtocolOutput(signature) => jni_util::serialize_to_jbyte_array(&env, &signature)
        }.unwrap_or_else(|_| std::ptr::null_mut())
    })).unwrap_or_else(|_| std::ptr::null_mut())
}

/// JNI for WRAPSLibraryBridge.verifySignatureImpl
#[no_mangle]
pub unsafe extern "system" fn Java_com_hedera_cryptography_wraps_WRAPSLibraryBridge_verifySignatureImpl(
    mut env: JNIEnv,
    _instance: JObject,
    schnorr_public_keys_jarray: JObjectArray,
    weights_jarray: JLongArray,
    node_ids_jarray: JLongArray,
    message_jarray: JByteArray,
    signature_jarray: JByteArray,
) -> jboolean {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let ab: AddressBook<E2> = match jni_util::build_address_book(&mut env, schnorr_public_keys_jarray, weights_jarray, node_ids_jarray) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false)
        };

        let message = match env.convert_byte_array(&message_jarray) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false)
        };

        let signature: SchnorrMultiSignature<E2> = match deserialize_from_jbyte_array(&env, &signature_jarray) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false)
        };

        match WRAPS::verify_signature(&ab, message, &signature) {
            Ok(val) => jboolean::from(val),
            Err(_) => return jboolean::from(false)
        }
    })).unwrap_or_else(|_| jboolean::from(false))
}

/// JNI for WRAPSLibraryBridge.hashAddressBookImpl
#[no_mangle]
pub unsafe extern "system" fn Java_com_hedera_cryptography_wraps_WRAPSLibraryBridge_hashAddressBookImpl(
    mut env: JNIEnv,
    _instance: JObject,
    schnorr_public_keys_jarray: JObjectArray,
    weights_jarray: JLongArray,
    node_ids_jarray: JLongArray,
) -> jbyteArray {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let ab: AddressBook<E2> = match jni_util::build_address_book(&mut env, schnorr_public_keys_jarray, weights_jarray, node_ids_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let hash: AddressBookHash<E2> = match WRAPS::compute_addressbook_hash(&ab) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        jni_util::serialize_to_jbyte_array(&env, &hash).unwrap_or_else(|_| std::ptr::null_mut())
    })).unwrap_or_else(|_| std::ptr::null_mut())
}

/// JNI for WRAPSLibraryBridge.hashArrayImpl
#[no_mangle]
pub unsafe extern "system" fn Java_com_hedera_cryptography_wraps_WRAPSLibraryBridge_hashArrayImpl(
    env: JNIEnv,
    _instance: JObject,
    input_jarray: JByteArray,
) -> jbyteArray {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if input_jarray.is_null() {
            return std::ptr::null_mut()
        }
        let input_vec: Vec<u8> = match env.convert_byte_array(&input_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };
        if input_vec.is_empty() {
            return std::ptr::null_mut()
        }

        let hash: HintsVKHash<E2> = WRAPS::compute_hints_vk_hash(&input_vec);

        jni_util::serialize_to_jbyte_array(&env, &hash).unwrap_or_else(|_| std::ptr::null_mut())
    })).unwrap_or_else(|_| std::ptr::null_mut())
}

/// JNI for WRAPSLibraryBridge.formatRotationMessageImpl
#[no_mangle]
pub unsafe extern "system" fn Java_com_hedera_cryptography_wraps_WRAPSLibraryBridge_formatRotationMessageImpl(
    mut env: JNIEnv,
    _instance: JObject,
    schnorr_public_keys_jarray: JObjectArray,
    weights_jarray: JLongArray,
    node_ids_jarray: JLongArray,
    tss_vk_jarray: JByteArray,
) -> jbyteArray {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let ab: AddressBook<E2> = match jni_util::build_address_book(&mut env, schnorr_public_keys_jarray, weights_jarray, node_ids_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let tss_vk_vec: Vec<u8> = match env.convert_byte_array(&tss_vk_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let msg = match WRAPS::compute_rotation_message(&ab, &tss_vk_vec) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        jni_util::u8_vec_to_jbyte_array(&env, &msg)
    })).unwrap_or_else(|_| std::ptr::null_mut())
}

/// JNI for WRAPSLibraryBridge.constructWrapsProofImpl
#[no_mangle]
pub unsafe extern "system" fn Java_com_hedera_cryptography_wraps_WRAPSLibraryBridge_constructWrapsProofImpl(
    mut env: JNIEnv,
    _instance: JObject,
    ab_genesis_hash_jarray: JByteArray,
    prev_schnorr_public_keys_jarray: JObjectArray,
    prev_weights_jarray: JLongArray,
    prev_node_ids_jarray: JLongArray,
    next_schnorr_public_keys_jarray: JObjectArray,
    next_weights_jarray: JLongArray,
    next_node_ids_jarray: JLongArray,
    prev_proof_jarray: JByteArray,
    tss_vk_jarray: JByteArray,
    signature_jarray: JByteArray,
) -> jbyteArray {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let ab_genesis_hash: AddressBookHash<E2> = match deserialize_from_jbyte_array(&env, &ab_genesis_hash_jarray) {
                Ok(val) => val,
                Err(_) => return std::ptr::null_mut()
        };

        let prev_ab: AddressBook<E2> = match jni_util::build_address_book(&mut env, prev_schnorr_public_keys_jarray, prev_weights_jarray, prev_node_ids_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let next_ab: AddressBook<E2> = match jni_util::build_address_book(&mut env, next_schnorr_public_keys_jarray, next_weights_jarray, next_node_ids_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let prev_proof: Option<Vec<u8>> = if prev_proof_jarray.is_null() { None } else {
            match env.convert_byte_array(&prev_proof_jarray) {
                Ok(val) => Some(val),
                Err(_) => return std::ptr::null_mut()
            }
        };

        let tss_vk_vec: Vec<u8> = match env.convert_byte_array(&tss_vk_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let signature: SchnorrMultiSignature<E2> = match deserialize_from_jbyte_array(&env, &signature_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let option_option_params = PUBLIC_PARAMS.get();
        if option_option_params.is_none() || option_option_params.unwrap().is_none() {
            return std::ptr::null_mut();
        }
        let public_params = option_option_params.unwrap().as_ref().unwrap();

        let (uncompressed_proof, compressed_proof): (Vec<u8>, Vec<u8>) = match WRAPS::construct_wraps_proof(
                public_params,
                &ab_genesis_hash,
                &prev_ab,
                &next_ab,
                prev_proof,
                tss_vk_vec,
                &signature) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let uncompressed_proof_jarray = jni_util::u8_vec_to_jbyte_array(&env, &uncompressed_proof);
        let compressed_proof_jarray = jni_util::u8_vec_to_jbyte_array(&env, &compressed_proof);

        let proof_clz = match env.find_class("com/hedera/cryptography/wraps/Proof") {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };
        let proof_obj = match env.new_object(proof_clz, "([B[B)V", &[JValue::from(&JObject::from_raw(uncompressed_proof_jarray)), JValue::from(&JObject::from_raw(compressed_proof_jarray))]) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        proof_obj.into_raw()
    })).unwrap_or_else(|_| std::ptr::null_mut())
}

/// JNI for WRAPSLibraryBridge.verifyCompressedProofImpl
#[no_mangle]
pub unsafe extern "system" fn Java_com_hedera_cryptography_wraps_WRAPSLibraryBridge_verifyCompressedProofImpl(
    env: JNIEnv,
    _instance: JObject,
    compressed_proof_jarray: JByteArray,
    ab_genesis_hash_jarray: JByteArray,
    tss_vk_jarray: JByteArray,
) -> jboolean {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let ab_genesis_hash: AddressBookHash<E2> = match deserialize_from_jbyte_array(&env, &ab_genesis_hash_jarray) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false)
        };

        let tss_vk_vec: Vec<u8> = match env.convert_byte_array(&tss_vk_jarray) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false)
        };

        let compressed_proof = match env.convert_byte_array(&compressed_proof_jarray) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false)
        };

        let option_compressed_verifying_key = COMPRESSED_VERIFYING_KEY.get_or_init(|| {
            let option_option_params = PUBLIC_PARAMS.get();
            if option_option_params.is_none() || option_option_params.unwrap().is_none() {
                return None;
            }
            let public_params = option_option_params.unwrap().as_ref().unwrap();

            match WRAPS::setup_compressed_verifier(public_params) {
                Ok(val) => Some(val),
                Err(_) => None
            }
        });

        let compressed_verifying_key = match option_compressed_verifying_key {
            Some(val) => val,
            None => return jboolean::from(false)
        };

        match WRAPS::verify_compressed_wraps_proof(compressed_verifying_key, &compressed_proof, &ab_genesis_hash, tss_vk_vec) {
            Ok(val) => jboolean::from(val),
            Err(_) => return jboolean::from(false)
        }
    })).unwrap_or_else(|_| jboolean::from(false))
}
