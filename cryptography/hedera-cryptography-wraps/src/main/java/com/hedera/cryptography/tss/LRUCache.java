// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.tss;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.function.Function;

/// A simple LRU cache implementation.
class LRUCache<K, V> {
    private final Map<K, V> cache = new HashMap<>();
    private final LinkedList<K> lru = new LinkedList<>();

    private final int size;

    /// Create new cache of a given size.
    LRUCache(int size) {
        this.size = size;
    }

    // MUST be synchronized on `cache` externally.
    private void accessKey(K key) {
        lru.remove(key);
        lru.addFirst(key);
    }

    /// Fetches or computes a value for a key,
    /// updating the LRU order and respecting the size.
    V get(K key, Function<K, V> computer) {
        synchronized (cache) {
            if (cache.containsKey(key)) {
                accessKey(key);
                return cache.get(key);
            }
        }

        final V value = computer.apply(key);

        synchronized (cache) {
            accessKey(key);

            if (cache.containsKey(key)) {
                return cache.get(key);
            }

            cache.put(key, value);
            if (cache.size() > size) {
                final K keyToEvict = lru.removeLast();
                cache.remove(keyToEvict);
            }

            return value;
        }
    }
}
