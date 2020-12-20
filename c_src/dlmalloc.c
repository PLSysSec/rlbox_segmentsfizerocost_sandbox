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
static uintptr_t sbrkEnd = PAGE_SIZE;
#define SEGMENT_SFI_HEAP_BITS 27
#define SEGMENT_SFI_HEAP_SIZE (1U << SEGMENT_SFI_HEAP_BITS)
static uintptr_t heap_end = SEGMENT_SFI_HEAP_SIZE - 1;

void segmentsfi_set_alternate_heap_base(void* sandbox_heap_base) {
    // This is the data segment setup we would use once sandboxing is fully setup
    // This is a workaround where we use the actual sandbox heap base in the full address space
    sbrkEnd = (uintptr_t)sandbox_heap_base + PAGE_SIZE;
    heap_end = (uintptr_t)sandbox_heap_base + SEGMENT_SFI_HEAP_SIZE - 1;
}

void* segmentsfi_sbrk(ssize_t size) {
    if (size == 0) {
        return (void*) sbrkEnd;
    } else if (size < 0) {
        return (void*) MFAIL;
    } else {
        uintptr_t new_end = sbrkEnd + size;
        if (new_end > heap_end) {
            return (void*) MFAIL;
        }
        else {
            uintptr_t oldsbrkEnd = sbrkEnd;
            sbrkEnd = new_end;
            return (void*) oldsbrkEnd;
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
