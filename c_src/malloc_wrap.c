#define USE_DL_PREFIX

#include "dlmalloc_inc.c"

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
