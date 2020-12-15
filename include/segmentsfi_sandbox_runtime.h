#pragma once

#include <stdint.h>
#include <memory>
#include <mutex>


extern "C" {
    void* __wrap_malloc(size_t size);
    void __wrap_free(void* ptr);
    void* __wrap_calloc(size_t num, size_t size);
    void* __wrap_realloc(void *ptr, size_t new_size);
}

class ldt_segment_resource {
    uint16_t segment_selector = 0;
    std::unique_ptr<char[]> mem = nullptr;

public:
    ldt_segment_resource(size_t pages);
    ~ldt_segment_resource();

    bool succesfully_initialized();
};

class sfisegment_sandbox {
    static bool ldts_initialized;
    static std::mutex segmentsfi_create_mutex;
    ldt_segment_resource stack_segment;
    ldt_segment_resource heap_segment;

    sfisegment_sandbox();
public:
    std::unique_ptr<sfisegment_sandbox> create_sandbox();
};

