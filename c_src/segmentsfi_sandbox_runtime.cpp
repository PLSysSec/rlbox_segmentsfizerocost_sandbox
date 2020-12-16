#include <sys/mman.h>

#include "segmentsfi_sandbox_runtime.h"
#include "rlbox_segmentsfi_sandbox.hpp"

#define USE_DL_PREFIX
// #define USE_LOCKS 1
#define MORECORE segmentsfi_sbrk
#define MORECORE_CANNOT_TRIM
#define HAVE_MMAP 0
#define HAVE_MREMAP 0
#include "dlmalloc_inc.c"

#include "ldt_manipulate_inc.cpp"
#include "mmap_aligned_inc.cpp"

void* __wrap_malloc(size_t size) {
    return segmentsfi_malloc(size);
}

void __wrap_free(void* ptr) {
    return segmentsfi_free(ptr);
}

void* __wrap_calloc(size_t num, size_t size) {
    return segmentsfi_calloc(num, size);
}

void* __wrap_realloc(void *ptr, size_t new_size) {
    return segmentsfi_realloc(ptr, new_size);
}

void* segmentsfi_malloc(size_t size) {
    return dlmalloc(size);
}

void segmentsfi_free(void* ptr) {
    return dlfree(ptr);
}

void* segmentsfi_calloc(size_t num, size_t size) {
    return dlcalloc(num, size);
}

void* segmentsfi_realloc(void *ptr, size_t new_size) {
    return dlrealloc(ptr, new_size);
}

void* segmentsfi_sbrk(ssize_t size) {
    segmentsfi_sandbox* s = rlbox::rlbox_segmentsfi_sandbox::get_active_segmentinfo_sandbox();
    return s->segmentsfi_sbrk(size);
}

#define PAGE_SIZE (1U << 12)
// heap is 128mb = 128 * 2^10 * 2^10 = 128 * 2^8 pages
#define HEAP_PAGES (128*(1U << 20)/PAGE_SIZE)

// returns true if succeeded
ldt_segment_resource::ldt_segment_resource(size_t pages) {
    mem_size = pages * PAGE_SIZE;
    mem = mmap_aligned(mem_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, mem_size /* alignment */, 0 /* alignment_offset */);

    if (mem == MAP_FAILED || mem == nullptr) {
        mem = nullptr;
    } else {
        segment_selector = NaClAllocateSegmentForDataRegion(mem, pages);
    }
}

bool ldt_segment_resource::succesfully_initialized() {
    return segment_selector != 0 && mem != nullptr;
}

ldt_segment_resource::~ldt_segment_resource() {
    if (mem != nullptr) {
        munmap(mem, mem_size);
        mem = nullptr;
    }
    if (segment_selector != 0) {
        NaClLdtDeleteSelector(segment_selector);
        segment_selector = 0;
    }
}

// statics
bool segmentsfi_sandbox::ldts_initialized = false;
std::mutex segmentsfi_sandbox::segmentsfi_create_mutex;

segmentsfi_sandbox::segmentsfi_sandbox() : heap_segment(HEAP_PAGES) {}

std::unique_ptr<segmentsfi_sandbox> segmentsfi_sandbox::create_sandbox() {
    const std::lock_guard<std::mutex> lock(segmentsfi_create_mutex);

    if (!ldts_initialized) {
        NaClLdtInitPlatformSpecific();
        ldts_initialized = true;
    }

    std::unique_ptr<segmentsfi_sandbox> ret;
    ret.reset(new segmentsfi_sandbox());
    if (!ret->heap_segment.succesfully_initialized()) {
        return nullptr;
    }

    ret->heap_start = ret->heap_segment.mem;
    ret->heap_end = (void*) (((uintptr_t)ret->heap_start) - 1 + ret->heap_segment.mem_size);
    // reserve the first page to ensure that null pointers fail as expected
    if (mprotect(ret->heap_start, PAGE_SIZE, PROT_NONE) == -1) {
        return nullptr;
    }
    ret->sbrkEnd = (void*) (((uintptr_t)ret->heap_start) + PAGE_SIZE);

    return ret;
}

void* segmentsfi_sandbox::get_heap_location() {
    return heap_start;
}
size_t segmentsfi_sandbox::get_heap_size() {
    return heap_segment.mem_size;
}

#ifndef MAX_SIZE_T
#define MAX_SIZE_T           (~(size_t)0)
#endif

#ifndef MFAIL
#define MFAIL                ((void*)(MAX_SIZE_T))
#endif

void* segmentsfi_sandbox::segmentsfi_sbrk(ssize_t size) {
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