// SPDX-License-Identifier: Apache-2.0

use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use ark_serialize::CanonicalDeserialize;
use jni::JNIEnv;
use jni::objects::JByteArray;

/// A cache for values deserializable from a JByteArray.
pub struct JNIMapCache<T: CanonicalDeserialize> {
    /// Cached values
    /// RwLock provides a thread-safe mutable cell.
    /// Option lets us start with the cache empty and avoids calling HashMap::new because
    /// this doesn't work in a static context.
    /// Arc allows us to share the value as a reference with callers of the get() function.
    option_map_cell: RwLock<Option<HashMap<Vec<u8>, Arc<T>>>>,
}

impl<T: CanonicalDeserialize> JNIMapCache<T> {
    /// Create a new cache instance.
    pub const fn new() -> JNIMapCache<T> {
        JNIMapCache {
            // The new() must be `const` so that we can initialize a `static` variable using it.
            // HashMap::new() cannot be called from a `const` function.
            // Therefore, we initialize the cell with None and create the map lazily.
            option_map_cell: RwLock::new(None),
        }
    }

    /// Get the cached value, and initialize it if necessary.
    pub fn get(&self, env: &JNIEnv, jarray: &JByteArray) -> Result<Arc<T>, Box<dyn Any>> {
        let vec = match env.convert_byte_array(&jarray) {
            Ok(val) => val,
            Err(err) => return Err(Box::new(err))
        };

        // Fast-path first, enclose in a {} block to release the read lock afterward:
        {
            let read_guard = self.option_map_cell.read().unwrap();
            if read_guard.is_some() {
                let option = read_guard.as_ref().unwrap().get(&vec);
                if option.is_some() {
                    return Ok(option.unwrap().clone());
                }
            }
        }

        // Slow-path: either the map doesn't exist, or the value isn't cached.
        let mut write_guard = self.option_map_cell.write().unwrap();
        if write_guard.is_none() {
            *write_guard = Some(HashMap::new());
        }

        let the_map = write_guard.as_mut().unwrap();
        if the_map.contains_key(&vec) {
            return Ok(the_map.get(&vec).unwrap().clone());
        }

        // Slowest-path: the value isn't cached yet:
        match T::deserialize_uncompressed(&*vec) {
            Ok(val) => {
                let arc = Arc::new(val);
                the_map.insert(vec, arc.clone());
                Ok(arc)
            },
            Err(err) => Err(Box::new(err))
        }
    }

    /// Clear cached values.
    pub fn reset(&self) {
        let mut write_guard = self.option_map_cell.write().unwrap();
        if write_guard.is_some() {
            write_guard.as_mut().unwrap().clear();
        }
    }
}
