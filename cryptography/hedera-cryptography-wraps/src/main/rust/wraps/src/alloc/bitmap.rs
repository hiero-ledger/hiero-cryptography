// SPDX-License-Identifier: Apache-2.0

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::cmp;

/// A map of SIZE bits that allows one to allocate/deallocate continuous regions of bits.
/// The SIZE must be a compile-time constant because Rust array sizes must be compile-time constants.
/// The implementation is not thread-safe. A client code is responsible for thread-safety.
pub struct BitMap<const SIZE: usize> {
    // For simplicity, and to avoid taking dependencies on bit-handling crates, we use a [bool].
    // This may not be super efficient. However, with our heap and block sizes, this results
    // in a very reasonable memory usage. E.g. our current 24GB/1KB=24MB, which is reasonable.
    bits: UnsafeCell<[bool; SIZE]>,

    // The tail index of the last allocated block.
    last_index: AtomicUsize
}

impl<const SIZE: usize> BitMap<SIZE> {
    pub const fn new() -> Self {
        BitMap {
            bits: UnsafeCell::new([false; SIZE]),
            last_index: AtomicUsize::new(0)
        }
    }

    /// Allocates `size` bits by flipping them to `true` and returns the start index.
    /// On error (zero size, "out of memory" - aka out of `false` bits, etc.), return usize::MAX.
    pub unsafe fn alloc(&self, size: usize) -> usize {
        if size == 0 {
            return usize::MAX
        }

        let bits_pointer = self.bits.get().cast::<bool>();

        // The search is generally O(N). However, if we always search from the very beginning after
        // having allocated a lot of memory, this effectively becomes an O(n^2) search for the
        // application as a whole.
        // So we maintain the `last_index` which points to the tail of the last allocated block,
        // i.e. it points to the first free block of memory, and we start the search from there.
        // This makes the effective complexity being O(N). In fact, in many cases, the application
        // experiences a complexity of O(1) when calling this search because we're likely to start
        // the search with the very beginning of the block being allocated. Provided we have enough
        // free blocks starting at this index, of course. Otherwise it's an honest O(N) search.
        // Experiments show that this does in fact improve the overall performance of the allocator,
        // especially as the block size becomes smaller, and hence the size of the bitmap becomes larger.
        let last_index_value = self.last_index.load(Ordering::Relaxed);
        // Search the tail first:
        let (mut index, first_true_index) = self.find_false_bits(bits_pointer, size, last_index_value, SIZE);
        if index >= SIZE && last_index_value != 0 {
            // If not found and we didn't start with 0 before, then search the head:
            (index, _) = self.find_false_bits(bits_pointer, size, 0, cmp::min(first_true_index, SIZE));
        }

        if index >= SIZE {
            return usize::MAX
        }

        // Remember where the allocated block ends. Next time, start search from there:
        let the_end = index + size;
        if the_end >= SIZE {
            self.last_index.store(0, Ordering::Relaxed);
        } else {
            self.last_index.store(the_end, Ordering::Relaxed);
        }

        for i in index..the_end {
            *bits_pointer.add(i) = true;
        }

        index
    }

    /// Deallocates `size` bits at `index` by flipping them to `false`.
    /// A client code is responsible for not deallocating bits that haven't been allocated in the first place.
    pub unsafe fn dealloc(&self, index: usize, size: usize) {
        // Try to prevent SEGFAULTs:
        if index >= SIZE || index+size > SIZE {
            return;
        }

        let bits_pointer = self.bits.get().cast::<bool>();
        for i in index..index+size {
            *bits_pointer.add(i) = false;
        }
    }

    /// Finds `size` continuous `false` bits and returns the start index, or usize::MAX.
    /// Argument `from` is inclusive, `to` is exclusive.
    /// Returns (the start index, the first true bit index)
    unsafe fn find_false_bits(&self, bits_pointer: *const bool, size: usize, from: usize, to: usize) -> (usize, usize) {
        // For safety:
        if to < from || size > to - from {
            return (usize::MAX, usize::MAX);
        }

        let mut cur = from;

        // Where to finish the second search later, if there's one:
        let mut first_true_index = usize::MAX;

        // Use + , don't use - , because unsigned values! If size > to, then to-size overflows.
        while cur + size <= to {
            if *bits_pointer.add(cur) {
                if first_true_index == usize::MAX {
                    first_true_index = cur;
                }
                cur += 1;
                continue
            }

            // bits[cur] is false here, so `cur` is a candidate start index now.

            // Small optimization for the smallest case to avoid extra loops/conditions below:
            if size == 1 {
                return (cur, first_true_index)
            }

            // Generic solution for size > 1
            let start = cur;
            cur += 1;
            while cur < start + size && cur < to && !*bits_pointer.add(cur) {
                cur += 1;
            }
            if cur == start + size && cur <= to {
                return (start, first_true_index)
            }

            // There's no `size` `false` bits at `start`.
            // Either cur >= to or bits[cur] == true here.
            // The loop condition and the `true` check at the top will handle that.
        }

        (usize::MAX, first_true_index)
    }
}
