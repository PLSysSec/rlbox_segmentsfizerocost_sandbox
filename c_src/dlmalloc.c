#include <stdint.h>
#include <unistd.h>

void* segmentsfi_sbrk(ssize_t size);

#define USE_DL_PREFIX
// #define USE_LOCKS 1
#define MORECORE segmentsfi_sbrk
#define MORECORE_CANNOT_TRIM
#define HAVE_MMAP 0
#define HAVE_MREMAP 0
#include "dlmalloc_inc.c"

#define PAGE_SIZE (1U << 12)
static void* sbrkEnd = (void*) PAGE_SIZE + 0x80000;
#define SEGMENT_SFI_HEAP_BITS 27
#define SEGMENT_SFI_HEAP_SIZE (1U << SEGMENT_SFI_HEAP_BITS)
const uintptr_t heap_end = SEGMENT_SFI_HEAP_SIZE - 1;

void* segmentsfi_sbrk(ssize_t size) {
    if(size == 0) {
        return (void*) ((uintptr_t)sbrkEnd);
    } else if(size < 0) {
        return (void*) MFAIL;
    } else {
        if(((uintptr_t)sbrkEnd+size) > ((uintptr_t)heap_end)) {
            return (void*) MFAIL;
        }
        else {
            void* oldsbrkEnd = sbrkEnd;
            sbrkEnd = (void*) ((uintptr_t)oldsbrkEnd + size);
            return oldsbrkEnd;
        }
    }
}

void* __wrap_malloc(size_t size) {
    return dlmalloc(size);
}

void __wrap_free(void* ptr) {
    return dlfree(ptr);
}

void* __wrap_calloc(size_t num, size_t size) {
    return dlcalloc(num, size);
}

void* __wrap_realloc(void *ptr, size_t new_size) {
    return dlrealloc(ptr, new_size);
}
