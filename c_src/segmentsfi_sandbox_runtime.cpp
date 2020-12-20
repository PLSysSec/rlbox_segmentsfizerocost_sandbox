#include <assert.h>

#include <sys/mman.h>

#include "segmentsfi_sandbox_runtime.h"
#include "rlbox_segmentsfi_sandbox.hpp"

#include "ldt_manipulate_inc.cpp"
#include "mmap_aligned_inc.cpp"
#include "proc_mapping_inc.cpp"

// returns true if succeeded
ldt_segment_resource::ldt_segment_resource(size_t pages) {
    mem_size = pages * PAGE_SIZE;
    mem = mmap_aligned(mem_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, mem_size /* alignment */, 0 /* alignment_offset */);

    if (mem == MAP_FAILED || mem == nullptr) {
        mem = nullptr;
    } else {
        data_segment_selector = NaClAllocateSegmentForDataRegion(mem, pages);
        code_segment_selector = NaClAllocateSegmentForCodeRegion(mem, pages);
    }
}

bool ldt_segment_resource::succesfully_initialized() {
    return data_segment_selector != 0 && code_segment_selector != 0 && mem != nullptr;
}

ldt_segment_resource::~ldt_segment_resource() {
    if (mem != nullptr) {
        munmap(mem, mem_size);
        mem = nullptr;
    }
    if (data_segment_selector != 0) {
        NaClLdtDeleteSelector(data_segment_selector);
        data_segment_selector = 0;
    }
    if (code_segment_selector != 0) {
        NaClLdtDeleteSelector(code_segment_selector);
        code_segment_selector = 0;
    }
}

// statics
bool segmentsfi_sandbox::ldts_initialized = false;
std::mutex segmentsfi_sandbox::segmentsfi_create_mutex;

segmentsfi_sandbox::segmentsfi_sandbox() : heap_segment(SEGMENT_SFI_HEAP_PAGES) {}

static int roundUpPow2(int numToRound, int multiple)
{
    assert(multiple && ((multiple & (multiple - 1)) == 0));
    return (numToRound + multiple - 1) & -multiple;
}

std::unique_ptr<segmentsfi_sandbox> segmentsfi_sandbox::create_sandbox(const char* libName, bool isFullPath, int flag) {
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

    ret->code_data_start = ((char*) ret->heap_start) + PAGE_SIZE;
    ret->remapped_lib = RemappedLib::create_remapped_lib(libName, isFullPath, flag, (char*) ret->code_data_start);

    if (ret->remapped_lib == nullptr) {
        return nullptr;
    }

    auto code_data_page_length = ret->remapped_lib->get_size();
    auto code_data_page_length_rounded = roundUpPow2(code_data_page_length, PAGE_SIZE);
    // set read write exec permsisions
    if (mprotect(ret->code_data_start, code_data_page_length_rounded, PROT_READ|PROT_WRITE|PROT_EXEC) == -1) {
        return nullptr;
    }
    return ret;
}
