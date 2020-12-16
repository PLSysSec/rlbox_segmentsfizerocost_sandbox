#pragma once

#include <stdint.h>
#include <memory>
#include <mutex>

class segmentsfi_sandbox;

extern "C" {
    void* dlmalloc(size_t size);
    void dlfree(void* ptr);
    void* dlcalloc(size_t num, size_t size);
    void* dlrealloc(void *ptr, size_t new_size);

    void* __wrap_malloc(size_t size);
    void __wrap_free(void* ptr);
    void* __wrap_calloc(size_t num, size_t size);
    void* __wrap_realloc(void *ptr, size_t new_size);

    void* segmentsfi_malloc(size_t size);
    void segmentsfi_free(void* ptr);
    void* segmentsfi_calloc(size_t num, size_t size);
    void* segmentsfi_realloc(void *ptr, size_t new_size);

    void* segmentsfi_sbrk(ssize_t size);
}

class ldt_segment_resource {
public:
    uint16_t segment_selector = 0;
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

    void* heap_start = nullptr;
    void* heap_end = nullptr;
    // The state variable for emulated sbrk. Indicates how far we have "sbrk"ed.
    void* sbrkEnd = nullptr;

    segmentsfi_sandbox();
public:
    static std::unique_ptr<segmentsfi_sandbox> create_sandbox();
    void* get_heap_location();
    size_t get_heap_size();
    void* segmentsfi_sbrk(ssize_t size);
};

