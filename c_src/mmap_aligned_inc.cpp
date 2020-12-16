#include <sys/mman.h>
#include <stdint.h>

// Note alignment must be a power of 2
static void* mmap_aligned(
    size_t requested_length,
    int prot,
    int flags,
    size_t alignment,
    size_t alignment_offset
) {
    size_t padded_length = requested_length + alignment + alignment_offset;
    uintptr_t unaligned = (uintptr_t) mmap(0, padded_length, prot, flags, -1, 0);

    // Round up the next address that has addr % alignment = 0
    uintptr_t aligned_nonoffset = (unaligned + (alignment - 1)) & ~(alignment - 1);

    // Currently offset 0 is aligned according to alignment
    // Alignment needs to be enforced at the given offset
    uintptr_t aligned = (aligned_nonoffset - alignment_offset >= unaligned)?
        (aligned_nonoffset - alignment_offset) :
        (aligned_nonoffset - alignment_offset + alignment);

    //Sanity check
    if (aligned < unaligned
        || (aligned + (requested_length - 1)) > (unaligned + (padded_length - 1))
        || (aligned + alignment_offset) % alignment != 0)
    {
        // explicitly ignore failures now, as this is just a best-effort clean up after the last fail
        munmap((void*) unaligned, padded_length);
        return 0;
    }

    {
        uintptr_t unused_front = aligned - unaligned;
        if (unused_front != 0) {
            if (munmap((void*) unaligned, unused_front) == -1) {
                // explicitly ignore failures now, as this is just a best-effort clean up after the last fail
                munmap((void*) unaligned, padded_length);
                return 0;
            }
        }
    }

    {
        uintptr_t unused_back = (unaligned + (padded_length - 1)) - (aligned + (requested_length - 1));
        if (unused_back != 0) {
            if (munmap((void*) (aligned + requested_length), unused_back) == -1) {
                // explicitly ignore failures now, as this is just a best-effort clean up after the last fail
                munmap((void*) unaligned, padded_length);
                return 0;
            }
        }
    }

    return (void*) aligned;
}
