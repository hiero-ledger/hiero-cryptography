// SPDX-License-Identifier: Apache-2.0

use std::any::Any;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use jni::JNIEnv;
use jni::objects::{JByteArray, JObject, JObjectArray};
use jni::sys::{jbyte, jbyteArray};
use crate::errors::HinTSError;
use crate::hints::{serialize, RANDOM_SIZE};

/// Creates a jbyteArray out of a Vec<jbyte> object.
/// # Arguments
/// * `env` - The JNI environment.
/// * `vec` the input vector
/// # Returns
/// *   a byte array with the input vector written, or null on error
pub fn jbyte_vec_to_jbyte_array(env: &JNIEnv, vec: &Vec<jbyte>) -> jbyteArray {
    let array = match env.new_byte_array(vec.len() as i32) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };
    match env.set_byte_array_region(&array, 0, &vec) {
        Ok(()) => array.into_raw(),
        Err(_) => {
            let _ = env.delete_local_ref(JObject::from(array));
            std::ptr::null_mut()
        }
    }
}

/// Creates a jbyteArray out of a Vec<u8> object.
/// # Arguments
/// * `env` - The JNI environment.
/// * `vec` the input vector
/// # Returns
/// *   a byte array with the input vector written, or null on error
pub fn u8_vec_to_jbyte_array(env: &JNIEnv, vec: &Vec<u8>) -> jbyteArray {
    let jbyte_vec = vec.iter().map(|&x| x as jbyte).collect();
    jbyte_vec_to_jbyte_array(env, &jbyte_vec)
}

/// Creates a jbyteArray out of a pair of Vec<u8> objects.
/// # Arguments
/// * `env` - The JNI environment.
/// * `vec1` the input vector 1
/// * `vec2` the input vector 2
/// # Returns
/// *   a byte array with all the vectors written one after another, or null on error
pub fn two_u8_vec_to_jbyte_array(env: &JNIEnv, vec1: &Vec<u8>, vec2: &Vec<u8>) -> jbyteArray {
    let jbyte_vec = vec1.iter().chain(vec2.iter()).map(|&x| x as jbyte).collect();
    jbyte_vec_to_jbyte_array(env, &jbyte_vec)
}

/// Reads a Java byte[][] into a vector of Vec<u8> objects.
/// # Arguments
/// * `env` - The JNI environment.
/// * `jarray` the Java array of byte arrays
/// # Returns
/// *   the byte arrays, or Err if the array or one of its elements is null or can't be read
pub fn jbyte_arrays_to_u8_vecs(env: &mut JNIEnv, jarray: &JObjectArray) -> Result<Vec<Vec<u8>>, ()> {
    let length = env.get_array_length(jarray).map_err(|_| ())?;
    let mut vecs = Vec::with_capacity(length as usize);
    for i in 0..length {
        let element = JByteArray::from(env.get_object_array_element(jarray, i).map_err(|_| ())?);
        let vec = env.convert_byte_array(&element);
        // A native method may only hold a few local references at once (16 are guaranteed), and an array can
        // have hundreds of elements, so release each one as soon as it's read.
        let _ = env.delete_local_ref(element);
        vecs.push(vec.map_err(|_| ())?);
    }
    Ok(vecs)
}


/// Creates a `[u8; RANDOM_SIZE]` array out of a given Java byte array,
/// which must be of size RANDOM_SIZE (currently 32).
/// # Arguments
/// * `env` - The JNI environment.
/// * `random_array` the Java byte array of size RANDOM_SIZE
/// # Returns
/// *   an entropy array as accepted by the CRS/HinTS implementation, or Err
pub fn build_entropy_array(env: &JNIEnv, random_array: &JByteArray) -> Result<[u8; RANDOM_SIZE], ()> {
    let random_vec = match env.convert_byte_array(&random_array) {
        Ok(val) => val,
        Err(_) => return Result::Err(())
    };
    let random_arr :[u8; RANDOM_SIZE] = match random_vec.try_into() {
        Ok(val) => val,
        Err(_) => return Result::Err(())
    };
    Ok(random_arr)
}

/// Deserializes a JByteArray into an object, or returns Err.
pub fn deserialize_jbyte_array<T: CanonicalDeserialize>(env: &JNIEnv, jarray: &JByteArray) -> Result<T, Box<dyn Any>> {
    let vec = match env.convert_byte_array(&jarray) {
        Ok(val) => val,
        Err(err) => return Err(Box::new(err))
    };
    match T::deserialize_uncompressed(&*vec) {
        Ok(val) => Ok(val),
        Err(err) => Err(Box::new(err))
    }
}

/// Serializes an object into a jbyteArray.
pub fn serialize_object<T: CanonicalSerialize>(env: &JNIEnv, obj: &T) -> Result<jbyteArray, HinTSError> {
    let vec = match serialize(obj) {
        Ok(val) => val,
        Err(e) => return Err(e)
    };
    Ok(u8_vec_to_jbyte_array(env, &vec))
}
