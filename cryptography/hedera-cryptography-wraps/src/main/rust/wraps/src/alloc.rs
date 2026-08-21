// SPDX-License-Identifier: Apache-2.0

mod filemap;
mod bitmap;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::UnsafeCell;
use std::sync::Mutex;

// Commented out on purpose. See a comment below where it's used.
use memmap2::{MmapMut /*, UncheckedAdvice*/};

use filemap::FileMap;
use bitmap::BitMap;

// As of 2025-12-10, RAM usage in GB with various parameters:
//
// Threshold \ Swap, GB |     16     |     20     |     24     |     30     |     40
// --------------------------------------------------------------------------------------
//    64 KB             |    7       |            |            |            |
//    32 KB             |    5.7     |            |            |            |
//    16 KB             |    5.6     |            |            |            |
//     8 KB             |    4.3     |            |            |            |
//     4 KB             |    3       |            |            |            |
//     2 KB             |    3.64    |    2.64    |            |            |
//     1 KB             |    4.9     |    2.59    |    1.73    |    1.86    |    1.86
//   512 B              |            |            |            |            |    1.83
//   256 B              |            |            |            |            |    1.79
//   128 B              |    5       |    2.69    |            |            |    1.73
//
// Note that the code doesn't really use more than about 16 GB of memory in total. However,
// a larger swap reduces the effect of fragmentation which normally results in allocating RAM
// instead of a space in the swap file. Hence the reason for testing with swap sizes >16 GB.
//
// Note that the system wouldn't run with a threshold of 64 bytes for unknown reason - likely
// because the bitmap boolean array becomes too large. We could consider switching from bool
// to u64 and using actual bits, but that would add unwanted complexity.
//
// Note that if the WRAPS implementation, or the memory allocator implementation change,
// some of the numbers may change too.
//
// As of now, 24 GB swap with a threshold of 1 KB seems the most reasonable combination:

/// Allocate small objects in RAM, larger objects on disk
const SIZE_THRESHOLD_BYTES: usize = 1024;

/// Disk file size in bytes, aka swap size. Unfortunately, this must be a compile-time constant.
const HEAP_SIZE_BYTES: u64 = 24 * 1024 * 1024 * 1024;

/// Allocation unit size in bytes. Heap size must be divisible by the block size.
const BLOCK_SIZE_BYTES: usize = SIZE_THRESHOLD_BYTES;

/// Number of blocks in the file on disk.
const NUM_OF_BLOCKS: usize = (HEAP_SIZE_BYTES / BLOCK_SIZE_BYTES as u64) as usize;

/// A memory allocator that attempts to allocate larger objects in a memory mapped file on disk.
pub struct MemmapAllocator {
    // BitMap needs to be thread-safe, so it's in a Mutex:
    bit_map: Mutex<BitMap<NUM_OF_BLOCKS>>,
    file_map: FileMap,
}

impl MemmapAllocator {
    pub const fn new() -> Self {
        MemmapAllocator {
            bit_map: Mutex::new(BitMap::new()),
            file_map: FileMap::new(HEAP_SIZE_BYTES)
        }
    }
}

// Required for allocators defined in static objects.
unsafe impl Sync for MemmapAllocator {}

/// The actual allocator implementation. In case the layout size is smaller than the threshold
/// or if any errors occur with the memory on disk, then fall back to using the system memory.
/// Try to never crash/panic/segfault.
unsafe impl GlobalAlloc for MemmapAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() >= SIZE_THRESHOLD_BYTES && self.file_map.get_map().is_some() {
            // Try the map
            let num_of_blocks = (layout.size() + BLOCK_SIZE_BYTES - 1) / BLOCK_SIZE_BYTES;

            // lock() blocks until the mutex is available; the only way it returns Err is
            // poisoning, i.e. a panic while the guard was held. Don't unwrap: in a global
            // allocator that panics again inside the panic machinery, which double panics
            // into an abort no catch_unwind can stop. Don't trust the bitmap either, since
            // a poisoned lock means it may be mid-update. Reporting NUM_OF_BLOCKS is how
            // this function already signals "no space", so a poisoned lock takes the same
            // path as a full bitmap and falls through to the system allocator below.
            // Also, put inside {} to release the lock ASAP.
            let index = {
                match self.bit_map.lock() {
                    Ok(mut bit_map) => bit_map.alloc(num_of_blocks),
                    Err(_) => NUM_OF_BLOCKS,
                }
            };
            if index < NUM_OF_BLOCKS {
                // unwrap() is safe because we checked is_some() above:
                return self.file_map.get_map().unwrap().as_mut_ptr().add(index * BLOCK_SIZE_BYTES)
            }
        }
        // If size is small or map is full, then use system RAM:
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if self.file_map.get_map().is_some() {
            // unwrap() is safe because we checked is_some() above:
            let start_ptr = self.file_map.get_map().unwrap().as_mut_ptr();
            let finish_ptr = start_ptr.add(HEAP_SIZE_BYTES as usize);
            if ptr >= start_ptr && ptr < finish_ptr {
                let offset = ptr.offset_from(start_ptr) as usize;
                let index = offset as usize / BLOCK_SIZE_BYTES;
                let num_of_blocks = (layout.size() + BLOCK_SIZE_BYTES - 1) / BLOCK_SIZE_BYTES;

                // The below operation is only supported on Linux currently, so we ignore any errors.
                // Any OS will eventually free this range anyway. This is just a hint:
                // unwrap() is safe because we checked is_some() above:
                // However, memmap actually doesn't export the UncheckedAdvice and this method on MS Windows,
                // and we happen to build this code on Windows. So unfortunately, we cannot use this:
                // let _ = self.file_map.get_map().unwrap().unchecked_advise_range(UncheckedAdvice::DontNeed, offset, layout.size());

                // lock() blocks until the mutex is available; Err means poisoning, so the
                // bitmap may be mid-update. Unlike alloc() we cannot fall back to the system
                // allocator, because this pointer belongs to the swap. Leave the block marked
                // as used instead: leaking swap space is the safe direction, whereas freeing
                // against a bitmap we don't trust could hand the same block out twice.
                if let Ok(mut bit_map) = self.bit_map.lock() {
                    bit_map.dealloc(index, num_of_blocks);
                }
                return;
            }
        }
        // If the pointer is outside the map or there's no map at all, then it's system RAM:
        System.dealloc(ptr, layout);
    }
}
