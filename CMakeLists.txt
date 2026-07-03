cmake_minimum_required(VERSION 3.16)
project(triangles-paper-wallet C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# CTest drives our test executables.
enable_testing()

# ---------------------------------------------------------------------------
# Reproducibility
# ---------------------------------------------------------------------------
if(NOT DEFINED ENV{SOURCE_DATE_EPOCH})
    set(SOURCE_DATE_EPOCH "1700000000")
endif()

# ---------------------------------------------------------------------------
# Security: refuse to build if libsecp256k1 is missing
# ---------------------------------------------------------------------------
if(NOT EXISTS "${CMAKE_SOURCE_DIR}/src/secp256k1/CMakeLists.txt")
    message(FATAL_ERROR
        "src/secp256k1 is empty. Re-clone with:\n"
        "    git submodule update --init --recursive\n"
        "Or re-clone the repo with --recurse-submodules.")
endif()

# ---------------------------------------------------------------------------
# libsecp256k1 configuration — must match triangles_v5 flags exactly so
# the derived keys are bit-identical to the daemon's own derivation.
# ---------------------------------------------------------------------------
set(SECP256K1_DISABLE_SHARED           ON  CACHE INTERNAL "")
set(SECP256K1_INSTALL                  OFF CACHE INTERNAL "")
set(SECP256K1_BUILD_BENCHMARK          OFF CACHE INTERNAL "")
set(SECP256K1_BUILD_TESTS              OFF CACHE INTERNAL "")
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS   OFF CACHE INTERNAL "")
set(SECP256K1_BUILD_CTIME_TESTS        OFF CACHE INTERNAL "")
set(SECP256K1_BUILD_EXAMPLES           OFF CACHE INTERNAL "")
set(SECP256K1_ENABLE_MODULE_ECDH       ON  CACHE INTERNAL "")
set(SECP256K1_ENABLE_MODULE_RECOVERY   ON  CACHE INTERNAL "")
set(SECP256K1_ENABLE_MODULE_EXTRAKEYS  OFF CACHE INTERNAL "")
set(SECP256K1_ENABLE_MODULE_SCHNORRSIG OFF CACHE INTERNAL "")
set(SECP256K1_ENABLE_MODULE_MUSIG      OFF CACHE INTERNAL "")

add_subdirectory(src/secp256k1 EXCLUDE_FROM_ALL)

# ---------------------------------------------------------------------------
# The CLI itself
# ---------------------------------------------------------------------------
add_subdirectory(src)
add_subdirectory(tests)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
message(STATUS "")
message(STATUS "triangles-paper-wallet configured:")
message(STATUS "  CLI          : src/triangles-mint-paper-wallet")
message(STATUS "  Test suites  : selftest, bip32_selftest, bip44_canonical, roundtrip, e2e_test")
message(STATUS "  Run all tests: ctest --test-dir build --output-on-failure")
message(STATUS "")
