#pragma once

#include <cstdint>
#include <cstdlib>
#include <dlfcn.h>
#include <mutex>
#ifndef RLBOX_USE_CUSTOM_SHARED_LOCK
#  include <shared_mutex>
#endif
#include <utility>

#include "rlbox_helpers.hpp"

#include "segmentsfi_sandbox_runtime.h"

namespace rlbox {

class rlbox_segmentsfi_sandbox;

struct rlbox_segmentsfi_sandbox_thread_data
{
  rlbox_segmentsfi_sandbox* sandbox;
  uint32_t last_callback_invoked;
};

#ifdef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES

rlbox_segmentsfi_sandbox_thread_data* get_rlbox_segmentsfi_sandbox_thread_data();
#  define RLBOX_MPK_SANDBOX_STATIC_VARIABLES()                                \
    thread_local rlbox::rlbox_segmentsfi_sandbox_thread_data                         \
      rlbox_segmentsfi_sandbox_thread_info{ 0, 0 };                                  \
    namespace rlbox {                                                          \
      rlbox_segmentsfi_sandbox_thread_data* get_rlbox_segmentsfi_sandbox_thread_data()     \
      {                                                                        \
        return &rlbox_segmentsfi_sandbox_thread_info;                                \
      }                                                                        \
    }                                                                          \
    static_assert(true, "Enforce semi-colon")

#endif

#define GET_CURR_DATA_SEGMENT(curr_ds) { \
  asm volatile("mov %%ds, %0\n\t"        \
            : "=r" (curr_ds)             \
            :                            \
            : );                         \
}

#define CHANGE_DATA_SEGMENT(ds) { \
  asm volatile("mov %0, %%ds\n\t" \
            :                     \
            : "r" (ds)            \
            : );                  \
}

/**
 * @brief Class that implements the segmentsfi sandbox.
 */
class rlbox_segmentsfi_sandbox
{
public:
  // Stick with the system defaults
  using T_LongLongType = long long;
  using T_LongType = long;
  using T_IntType = int;
  using T_PointerType = void*;
  using T_ShortType = short;
  // You can transfer buffers at the page level with segmentsfi
  // But this is too expensive as it involves a syscall
  // Copies are usually faster, so no transfer support
  // using can_grant_deny_access = void;

private:
  std::unique_ptr<segmentsfi_sandbox> segment_info = nullptr;
  void* sandbox = nullptr;

  uint16_t segmentsfi_app_domain = 0;
  uint16_t segmentsfi_sbx_domain = 0;

  RLBOX_SHARED_LOCK(callback_mutex);
  static inline const uint32_t MAX_CALLBACKS = 64;
  void* callback_unique_keys[MAX_CALLBACKS]{ 0 };
  void* callbacks[MAX_CALLBACKS]{ 0 };

#ifndef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
  thread_local static inline rlbox_segmentsfi_sandbox_thread_data thread_data{ 0, 0 };
#endif

  template<uint32_t N, typename T_Ret, typename... T_Args>
  static T_Ret callback_trampoline(T_Args... params)
  {
#ifdef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
    auto& thread_data = *get_rlbox_segmentsfi_sandbox_thread_data();
#endif
    CHANGE_DATA_SEGMENT(thread_data.sandbox->segmentsfi_app_domain);
    thread_data.last_callback_invoked = N;
    using T_Func = T_Ret (*)(T_Args...);
    T_Func func;
    {
      RLBOX_ACQUIRE_SHARED_GUARD(lock, thread_data.sandbox->callback_mutex);
      func = reinterpret_cast<T_Func>(thread_data.sandbox->callbacks[N]);
    }
    // Callbacks are invoked through function pointers, cannot use std::forward
    // as we don't have caller context for T_Args, which means they are all
    // effectively passed by value
    return func(params...);
  }

protected:
  inline void impl_create_sandbox(const char* path) {
    sandbox = dlopen(path, RTLD_LAZY | RTLD_LOCAL);
    if (sandbox == nullptr) {
      char* error = dlerror();
      detail::dynamic_check(sandbox != nullptr, error);
    }

    segment_info = segmentsfi_sandbox::create_sandbox();
    detail::dynamic_check(segment_info != nullptr, "Setting up segments failed");

    GET_CURR_DATA_SEGMENT(segmentsfi_app_domain);
    segmentsfi_sbx_domain = segment_info->get_heap_segment();
  }

  inline void impl_destroy_sandbox() {
    dlclose(sandbox);
  }

  template<typename T>
  inline void* impl_get_unsandboxed_pointer(T_PointerType p) const
  {
    auto heap_base = segment_info->get_heap_location();
    auto ret = ((uintptr_t)heap_base) + ((uintptr_t)p);
    return (void*) ret;
  }

  template<typename T>
  inline T_PointerType impl_get_sandboxed_pointer(const void* p) const
  {
    auto ret = ((uintptr_t)p) & (SEGMENT_SFI_HEAP_SIZE - 1);
    return (T_PointerType) ret;
  }

  template<typename T>
  static inline void* impl_get_unsandboxed_pointer_no_ctx(
    T_PointerType p,
    const void* example_unsandboxed_ptr,
    rlbox_segmentsfi_sandbox* (* /* expensive_sandbox_finder */)(
      const void* example_unsandboxed_ptr))
  {
    auto p_val = (uintptr_t)p;
    auto heap_base = p_val & ~(SEGMENT_SFI_HEAP_SIZE - 1);
    auto ret = ((uintptr_t)heap_base) + p_val;
    return (void*) ret;
  }

  template<typename T>
  static inline T_PointerType impl_get_sandboxed_pointer_no_ctx(
    const void* p,
    const void* /* example_unsandboxed_ptr */,
    rlbox_segmentsfi_sandbox* (*/* expensive_sandbox_finder */)(
      const void* example_unsandboxed_ptr))
  {
    auto ret = ((uintptr_t)p) & (SEGMENT_SFI_HEAP_SIZE - 1);
    return (T_PointerType) ret;
  }

  static inline bool impl_is_in_same_sandbox(const void*, const void*)
  {
    return true;
  }

  inline bool impl_is_pointer_in_sandbox_memory(const void*) { return true; }
  inline bool impl_is_pointer_in_app_memory(const void*) { return true; }

  inline size_t impl_get_total_memory()
  {
    return std::numeric_limits<size_t>::max();
  }

  inline void* impl_get_memory_location()
  {
    // There isn't any sandbox memory for the segmentsfi_sandbox as we just redirect
    // to the app. Also, this is mostly used for pointer swizzling or sandbox
    // bounds checks which is also not present/not required. So we can just
    // return null
    return nullptr;
  }

  template<typename T = void>
  void* impl_lookup_symbol(const char* func_name)
  {
    auto ret = dlsym(sandbox, func_name);
    detail::dynamic_check(ret != nullptr, "Symbol not found");
    return ret;
  }

  template<typename T, typename T_Converted, typename... T_Args>
  auto impl_invoke_with_func_ptr(T_Converted* func_ptr, T_Args&&... params)
  {
#ifdef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
    auto& thread_data = *get_rlbox_segmentsfi_sandbox_thread_data();
#endif
    thread_data.sandbox = this;
    CHANGE_DATA_SEGMENT(segmentsfi_sbx_domain);
    return (*func_ptr)(params...);
  }

  template<typename T_Ret, typename... T_Args>
  inline T_PointerType impl_register_callback(void* key, void* callback)
  {
    RLBOX_ACQUIRE_UNIQUE_GUARD(lock, callback_mutex);

    void* chosen_trampoline = nullptr;

    // need a compile time for loop as we we need I to be a compile time value
    // this is because we are returning the I'th callback trampoline
    detail::compile_time_for<MAX_CALLBACKS>([&](auto I) {
      if (!chosen_trampoline && callback_unique_keys[I.value] == nullptr) {
        callback_unique_keys[I.value] = key;
        callbacks[I.value] = callback;
        chosen_trampoline = reinterpret_cast<void*>(
          callback_trampoline<I.value, T_Ret, T_Args...>);
      }
    });

    return reinterpret_cast<T_PointerType>(chosen_trampoline);
  }

  inline T_PointerType impl_malloc_in_sandbox(size_t size)
  {
    #ifdef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
    auto& thread_data = *get_rlbox_segmentsfi_sandbox_thread_data();
#endif
    thread_data.sandbox = this;
    T_PointerType ret = segmentsfi_malloc(size);
    return ret;
  }

  inline void impl_free_in_sandbox(T_PointerType p)
  {
    #ifdef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
    auto& thread_data = *get_rlbox_segmentsfi_sandbox_thread_data();
#endif
    thread_data.sandbox = this;
    segmentsfi_free(p);
  }

  static inline std::pair<rlbox_segmentsfi_sandbox*, void*>
  impl_get_executed_callback_sandbox_and_key()
  {
#ifdef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
    auto& thread_data = *get_rlbox_segmentsfi_sandbox_thread_data();
#endif
    auto sandbox = thread_data.sandbox;
    auto callback_num = thread_data.last_callback_invoked;
    void* key = sandbox->callback_unique_keys[callback_num];
    return std::make_pair(sandbox, key);
  }

  template<typename T_Ret, typename... T_Args>
  inline void impl_unregister_callback(void* key)
  {
    RLBOX_ACQUIRE_UNIQUE_GUARD(lock, callback_mutex);
    for (uint32_t i = 0; i < MAX_CALLBACKS; i++) {
      if (callback_unique_keys[i] == key) {
        callback_unique_keys[i] = nullptr;
        callbacks[i] = nullptr;
        break;
      }
    }
  }

  template<typename T>
  inline T* impl_grant_access(T* src, size_t num, bool& success)
  {
    RLBOX_UNUSED(num);
    success = true;
    return src;
  }

  template<typename T>
  inline T* impl_deny_access(T* src, size_t num, bool& success)
  {
    RLBOX_UNUSED(num);
    success = true;
    return src;
  }
public:

  static segmentsfi_sandbox* get_active_segmentinfo_sandbox()
  {
#ifdef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
    auto& thread_data = *get_rlbox_segmentsfi_sandbox_thread_data();
#endif
    return thread_data.sandbox->segment_info.get();
  }
};

}
