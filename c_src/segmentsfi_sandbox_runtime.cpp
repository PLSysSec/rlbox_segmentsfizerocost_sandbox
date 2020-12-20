#include <sys/mman.h>

#include "segmentsfi_sandbox_runtime.h"

#include "ldt_manipulate_inc.cpp"
#include "mmap_aligned_inc.cpp"

// returns true if succeeded
ldt_segment_resource::ldt_segment_resource(size_t pages) {
    mem_size = pages * PAGE_SIZE;
    mem = mmap_aligned(mem_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, mem_size /* alignment */, 0 /* alignment_offset */);

    if (mem == MAP_FAILED || mem == nullptr) {
        mem = nullptr;
    } else {
        // This is the data segment setup we would use once sandboxing is fully setup
        // segment_selector = NaClAllocateSegmentForDataRegion(mem, pages);
        // This is a workaround that allows access to the full memory
        segment_selector = NaClAllocateSegmentForDataRegion(nullptr, 1U<<20);
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

segmentsfi_sandbox::segmentsfi_sandbox() : heap_segment(SEGMENT_SFI_HEAP_PAGES) {}

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
    // reserve the first page to ensure that null pointers fail as expected
    if (mprotect(ret->heap_start, PAGE_SIZE, PROT_NONE) == -1) {
        return nullptr;
    }

    return ret;
}
