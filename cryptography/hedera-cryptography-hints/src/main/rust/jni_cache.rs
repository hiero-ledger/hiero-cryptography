// SPDX-License-Identifier: Apache-2.0

use std::any::Any;
use std::collections::{HashMap, LinkedList};
use std::sync::{Arc, RwLock};
use ark_serialize::CanonicalDeserialize;
use jni::JNIEnv;
use jni::objects::JByteArray;

/// A cache for values deserializable from a JByteArray.
pub struct JNIMapCache<T: CanonicalDeserialize, const SIZE: usize> {
    /// Cached values
    /// RwLock provides a thread-safe mutable cell.
    /// Option lets us start with the cache empty and avoids calling HashMap::new because
    /// this doesn't work in a static context.
    /// Arc allows us to share the value as a reference with callers of the get() function.
    option_map_cell: RwLock<Option<HashMap<Vec<u8>, Arc<T>>>>,

    lru_list: RwLock<Option<LinkedList<Vec<u8>>>>,
}

impl<T: CanonicalDeserialize, const SIZE: usize> JNIMapCache<T, SIZE> {
    /// Create a new cache instance.
    pub const fn new() -> JNIMapCache<T, SIZE> {
        JNIMapCache {
            // The new() must be `const` so that we can initialize a `static` variable using it.
            // HashMap::new() cannot be called from a `const` function.
            // Therefore, we initialize the cell with None and create the map lazily.
            option_map_cell: RwLock::new(None),

            lru_list: RwLock::new(None),
        }
    }

    /// Pushes the lru key to the back of the list, and returns Some(pop_front()) if full,
    /// or None otherwise.
    fn access_key(&self, key: &Vec<u8>/*[u8]*/) -> Option<Vec<u8>> {
        let mut write_guard = self.lru_list.write().unwrap();
        if write_guard.is_none() {
            *write_guard = Some(LinkedList::new());
        }

        let the_list = write_guard.as_mut().unwrap();
        if !the_list.is_empty() && the_list.back().unwrap() == key {
            return None;
        }

        let _ = the_list.extract_if(|v| v == key);
        the_list.push_back(key.clone());

        if the_list.len() > SIZE {
            return Some(the_list.pop_front().unwrap())
        }

        None
    }

    /// Get the cached value, and initialize it if necessary.
    pub fn get(&self, env: &JNIEnv, jarray: &JByteArray) -> Result<Arc<T>, Box<dyn Any>> {
        let vec = match env.convert_byte_array(&jarray) {
            Ok(val) => val,
            Err(err) => return Err(Box::new(err))
        };

        match self.access_key(&vec) {
            Some(key_to_evict) => {
                let mut write_guard = self.option_map_cell.write().unwrap();
                if !write_guard.is_none() {
                    write_guard.as_mut().unwrap().remove(&key_to_evict);
                }
            },
            None => {}
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
        // First, deserialize the value w/o any locks:
        let arc = match T::deserialize_uncompressed(&*vec) {
            Ok(val) => Arc::new(val),
            Err(err) => return Err(Box::new(err))
        };

        // Then take the write() lock and insert it if absent:
        let mut write_guard = self.option_map_cell.write().unwrap();
        if write_guard.is_none() {
            *write_guard = Some(HashMap::new());
        }

        let the_map = write_guard.as_mut().unwrap();
        if the_map.contains_key(&vec) {
            // Another thread inserted the value already, so we drop our arc from above.
            return Ok(the_map.get(&vec).unwrap().clone());
        }

        the_map.insert(vec, arc.clone());
        Ok(arc)
    }

    /// Clear cached values.
    pub fn reset(&self) {
        let mut write_guard = self.option_map_cell.write().unwrap();
        if write_guard.is_some() {
            write_guard.as_mut().unwrap().clear();
        }
    }
}
