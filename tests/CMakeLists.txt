# triangles-paper-wallet/tests/CMakeLists.txt
#
# Test executables that link against the same library units as the
# main CLI. They have NO dependency on the CLI's main.c.

# Common compile options for all tests (mirror the CLI's strict policy).
set(TEST_CFLAGS
    -D_POSIX_C_SOURCE=200809L
    -Wall -Wextra -Wpedantic -Wshadow
    -Wmissing-prototypes -Wstrict-prototypes
    -Wcast-align -Wformat=2
    "-D_FORTIFY_SOURCE=2"
    "-fstack-protector-strong"
    "-fno-ident"
)

set(TEST_SRC
    ${CMAKE_SOURCE_DIR}/src/sha256.c
    ${CMAKE_SOURCE_DIR}/src/ripemd160.c
    ${CMAKE_SOURCE_DIR}/src/pbkdf2.c
    ${CMAKE_SOURCE_DIR}/src/tri_sha512.c
    ${CMAKE_SOURCE_DIR}/src/base58.c
    ${CMAKE_SOURCE_DIR}/src/entropy.c
    ${CMAKE_SOURCE_DIR}/src/bip32.c
    ${CMAKE_SOURCE_DIR}/src/bip39.c
    ${CMAKE_SOURCE_DIR}/src/bip44.c
    ${CMAKE_SOURCE_DIR}/tests/test_helpers.c
)

set(TEST_INCLUDES
    -I ${CMAKE_SOURCE_DIR}/src
    -I ${CMAKE_SOURCE_DIR}/tests
    -I ${CMAKE_SOURCE_DIR}/src/secp256k1/include
)

# ---------------------------------------------------------------------
# selftest — 11 canonical crypto vector checks (RFC, BIP39, Bitcoin).
# ---------------------------------------------------------------------
add_executable(selftest
    ${CMAKE_SOURCE_DIR}/tests/selftest.c
    ${TEST_SRC}
)
target_compile_options(selftest PRIVATE ${TEST_CFLAGS})
target_include_directories(selftest PRIVATE ${TEST_INCLUDES})
target_link_libraries(selftest PRIVATE secp256k1 crypto pthread)
target_link_options(selftest PRIVATE
    "-Wl,--no-undefined"
    "-Wl,-z,relro" "-Wl,-z,now"
    "-Wl,--as-needed"
)
add_test(NAME paper_selftest COMMAND selftest)

# ---------------------------------------------------------------------
# bip32_selftest — BIP32 spec vectors 1 + 2.
# ---------------------------------------------------------------------
add_executable(bip32_selftest
    ${CMAKE_SOURCE_DIR}/tests/bip32_selftest.c
    ${TEST_SRC}
)
target_compile_options(bip32_selftest PRIVATE ${TEST_CFLAGS})
target_include_directories(bip32_selftest PRIVATE ${TEST_INCLUDES})
target_link_libraries(bip32_selftest PRIVATE secp256k1 crypto pthread)
add_test(NAME paper_bip32 COMMAND bip32_selftest)

# ---------------------------------------------------------------------
# bip44_canonical — first address cross-check against Python's ecdsa.
# ---------------------------------------------------------------------
add_executable(bip44_canonical
    ${CMAKE_SOURCE_DIR}/tests/bip44_canonical.c
    ${TEST_SRC}
)
target_compile_options(bip44_canonical PRIVATE ${TEST_CFLAGS})
target_include_directories(bip44_canonical PRIVATE ${TEST_INCLUDES})
target_link_libraries(bip44_canonical PRIVATE secp256k1 crypto pthread)
add_test(NAME paper_bip44_canonical COMMAND bip44_canonical)

# ---------------------------------------------------------------------
# roundtrip — abandon×11+about → TDrHzzu8pwHh1i4p2UwCFcQi3ktsBXpDDy.
# ---------------------------------------------------------------------
add_executable(roundtrip
    ${CMAKE_SOURCE_DIR}/tests/roundtrip.c
    ${TEST_SRC}
)
target_compile_options(roundtrip PRIVATE ${TEST_CFLAGS})
target_include_directories(roundtrip PRIVATE ${TEST_INCLUDES})
target_link_libraries(roundtrip PRIVATE secp256k1 crypto pthread)
add_test(NAME paper_roundtrip COMMAND roundtrip)

# ---------------------------------------------------------------------
# e2e_test — comprehensive 12-case paper-wallet invariant suite.
# Catches production bugs (wordlist, entropy overflow, base58 DECODE_MAP).
# ---------------------------------------------------------------------
add_executable(e2e_test
    ${CMAKE_SOURCE_DIR}/tests/e2e_test.c
    ${TEST_SRC}
)
target_compile_options(e2e_test PRIVATE ${TEST_CFLAGS})
target_include_directories(e2e_test PRIVATE ${TEST_INCLUDES})
target_link_libraries(e2e_test PRIVATE secp256k1 crypto pthread)
add_test(NAME paper_e2e COMMAND e2e_test)
# e2e uses CSPRNG — set property to not fail on transient issues.
set_tests_properties(paper_e2e PROPERTIES TIMEOUT 30)
