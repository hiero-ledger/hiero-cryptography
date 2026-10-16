// SPDX-License-Identifier: Apache-2.0

use std::any::Any;
use std::collections::{HashMap, LinkedList};
use std::hash::Hash;
use std::sync::{Arc, RwLock};
use ark_serialize::CanonicalDeserialize;
use jni::JNIEnv;
use jni::objects::JByteArray;

/// An internal, not synchronized implementation of an LRU cache.
/// A client-facing cache API wrapper is responsible for synchronization.
struct LRUCache<K: Eq + PartialEq + Hash + Clone, V, const SIZE: usize> {
    /// Arc allows us to share the value as a reference with clients.
    cache_map: HashMap<K, Arc<V>>,

    lru_list: LinkedList<K>
}

impl<K: Eq + PartialEq + Hash + Clone, V, const SIZE: usize> LRUCache<K, V, SIZE> {
    fn new() -> Self {
        LRUCache {
            cache_map: HashMap::new(),
            lru_list: LinkedList::new(),
        }
    }

    /// LRU bookkeeping.
    fn push_back_key(&mut self, key: &K) {
        self.lru_list.extract_if(|v| v == key).for_each(drop);
        self.lru_list.push_back(key.clone());
    }

    /// If hit, do LRU bookkeeping and return Some(Arc), otherwise None.
    fn get_if_hit(&mut self, key: &K) -> Option<Arc<V>> {
        let option_arc_clone = match self.cache_map.get(key) {
            Some(v) => Some(v.clone()),
            None => return None
        };
        self.push_back_key(key);
        option_arc_clone
    }

    /// Insert the (K, V) if missing and return an Arc<V>,
    /// performing LRU bookkeeping and managing the cache size.
    fn insert(&mut self, key: &K, value: V) -> Arc<V> {
        let try_hit = self.get_if_hit(key);
        if try_hit.is_some() {
            return try_hit.unwrap();
        }

        let arc = Arc::new(value);
        self.push_back_key(key);
        self.cache_map.insert(key.clone(), arc.clone());

        if self.lru_list.len() > SIZE {
            let key_to_evict = self.lru_list.pop_front();
            self.cache_map.remove(&key_to_evict.unwrap());
        }

        // This should not panic because the outer wrapper synchronizes access:
        assert_eq!(self.lru_list.len(), self.cache_map.len());

        arc
    }

    /// Clear the cache.
    fn reset(&mut self) {
        self.lru_list.clear();
        self.cache_map.clear();
    }
}

/// A cache for values deserializable from a JByteArray.
/// This is a wrapper around an LRUCache object that orchestrates synchronization.
pub struct JNIMapCache<T: CanonicalDeserialize, const SIZE: usize> {
    /// RwLock provides a thread-safe mutable cell.
    /// Option lets us start with the cache empty and avoids calling HashMap::new because
    /// this doesn't work in a static context.
    option_cache_cell: RwLock<Option<LRUCache<Vec<u8>, T, SIZE>>>,
}

impl<T: CanonicalDeserialize, const SIZE: usize> JNIMapCache<T, SIZE> {
    /// Create a new cache instance.
    pub const fn new() -> JNIMapCache<T, SIZE> {
        JNIMapCache {
            // The new() must be `const` so that we can initialize a `static` variable using it.
            // LRUCache::new() cannot be called from a `const` function.
            // Therefore, we initialize the cell with None and create the cache lazily.
            option_cache_cell: RwLock::new(None),
        }
    }

    /// Get the cached value, and initialize it if necessary.
    pub fn get(&self, env: &JNIEnv, jarray: &JByteArray) -> Result<Arc<T>, Box<dyn Any>> {
        let vec = match env.convert_byte_array(&jarray) {
            Ok(val) => val,
            Err(err) => return Err(Box::new(err))
        };

        // Fast-path: see if this is a cache hit:
        {
            let mut guard = self.option_cache_cell.write().unwrap();
            if guard.is_none() {
                *guard = Some(LRUCache::new());
            } else {
                let option_arc= guard.as_mut().unwrap().get_if_hit(&vec);
                if option_arc.is_some() {
                    return Ok(option_arc.unwrap());
                }
            }
        }

        // It's a cache miss. Slow deserialization is happening outside any locks:
        let val = match T::deserialize_uncompressed(&*vec) {
            Ok(val) => val,
            Err(err) => return Err(Box::new(err))
        };

        let mut guard = self.option_cache_cell.write().unwrap();
        Ok(guard.as_mut().unwrap().insert(&vec, val))
    }

    /// Clear cached values.
    pub fn reset(&self) {
        let mut write_guard = self.option_cache_cell.write().unwrap();
        if write_guard.is_some() {
            write_guard.as_mut().unwrap().reset();
        }
    }
}
