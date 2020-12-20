#pragma once

#include <stdint.h>
#include <memory>
#include <mutex>

#define PAGE_SIZE (1U << 12)
// Keep heap consistent with dlmalloc.c
// heap is 128mb = 2^7 * 2^10 * 2^10
#define SEGMENT_SFI_HEAP_BITS 27
#define SEGMENT_SFI_HEAP_SIZE (1U << SEGMENT_SFI_HEAP_BITS)
#define SEGMENT_SFI_HEAP_PAGES (SEGMENT_SFI_HEAP_SIZE/PAGE_SIZE)

class RemappedLib {
private:
    void* libBase;
    uint32_t offset;
    uint64_t length;
    void* originalLib = nullptr;
    void* originalLibBase;
public:
    static std::unique_ptr<RemappedLib> create_remapped_lib(const char* libName, bool isFullPath, int flag, char* target);
    void* symbol_lookup(const char *symbol);
    uint64_t get_size() { return length; }
    ~RemappedLib();
};

class ldt_segment_resource {
public:
    uint16_t data_segment_selector = 0;
    uint16_t code_segment_selector = 0;
    void* mem = nullptr;
    size_t mem_size = 0;

    ldt_segment_resource(size_t pages);
    ~ldt_segment_resource();

    bool succesfully_initialized();
};

class segmentsfi_sandbox {
    static bool ldts_initialized;
    static std::mutex segmentsfi_create_mutex;
    ldt_segment_resource heap_segment;
    std::unique_ptr<RemappedLib> remapped_lib;
    void* heap_start = nullptr;
    void* code_data_start = nullptr;

    segmentsfi_sandbox();
public:
    static std::unique_ptr<segmentsfi_sandbox> create_sandbox(const char* libName, bool isFullPath, int flag);
    inline void* get_heap_location() {
        return heap_start;
    }
    inline size_t get_heap_size() {
        return heap_segment.mem_size;
    }

    inline uintptr_t get_sandboxed_pointer(uintptr_t ptr) {
        auto ret = ptr & (SEGMENT_SFI_HEAP_SIZE - 1);
        return ret;
    }

    inline uintptr_t get_unsandboxed_pointer(uintptr_t ptr) {
        auto ret = (((uintptr_t)heap_start) & ~(SEGMENT_SFI_HEAP_SIZE - 1)) + ptr;
        return ret;
    }

    inline uint16_t get_heap_segment() {
        return heap_segment.data_segment_selector;
    }

    inline uint16_t get_code_segment() {
        return heap_segment.code_segment_selector;
    }

    void* symbol_lookup(const char *symbol) {
        return remapped_lib->symbol_lookup(symbol);
    }
};

