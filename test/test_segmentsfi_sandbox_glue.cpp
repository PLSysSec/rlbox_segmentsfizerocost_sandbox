// NOLINTNEXTLINE
#define RLBOX_USE_EXCEPTIONS
#define RLBOX_ENABLE_DEBUG_ASSERTIONS
#define RLBOX_SINGLE_THREADED_INVOCATIONS
#include "rlbox_segmentsfi_sandbox.hpp"

// NOLINTNEXTLINE
#define TestName "rlbox_segmentsfi_sandbox"
// NOLINTNEXTLINE
#define TestType rlbox::rlbox_segmentsfi_sandbox

#ifndef GLUE_LIB_PATH
#  error "Missing definition for GLUE_LIB_PATH"
#endif

// NOLINTNEXTLINE
#define CreateSandbox(sandbox) sandbox.create_sandbox(GLUE_LIB_PATH)
#include "test_sandbox_glue.inc.cpp"
