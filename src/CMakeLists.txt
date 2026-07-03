# triangles-paper-wallet/src/CMakeLists.txt
#
# Thin wrapper around vendored libsecp256k1.
# SHA-256, RIPEMD-160, Base58, BIP39, BIP32, BIP44 are vendored here.
# SHA-512 and HMAC-SHA512 use OpenSSL EVP via src/tri_sha512.c (FIPS-correct).

set(SRCS
    main.c
    paper.c
    entropy.c
    bip39.c
    bip32.c
    bip44.c
    pbkdf2.c
    tri_sha512.c
    sha256.c
    ripemd160.c
    base58.c
)

add_executable(triangles-mint-paper-wallet ${SRCS})

target_compile_options(triangles-mint-paper-wallet PRIVATE
    -Wall -Wextra -Wpedantic -Wshadow
    -Wmissing-prototypes -Wstrict-prototypes
    -Wcast-align -Wformat=2
    "-D_FORTIFY_SOURCE=2"
    "-fstack-protector-strong"
    "-fno-ident"
    "-fvisibility=hidden"
)

# Link against libsecp256k1 + OpenSSL EVP for SHA-512/HMAC-SHA-512.
target_link_libraries(triangles-mint-paper-wallet PRIVATE
    secp256k1
    crypto
)

# No-exec-stack + RELRO + bind-now.
target_link_options(triangles-mint-paper-wallet PRIVATE
    "-Wl,--no-undefined"
    "-Wl,-z,relro"
    "-Wl,-z,now"
    "-Wl,-z,noexecstack"
    "-Wl,--as-needed"
)

install(TARGETS triangles-mint-paper-wallet
    RUNTIME DESTINATION bin)

# Make sure the test executables are actually built when ctest runs.
add_custom_target(paper_tests ALL
    DEPENDS selftest bip32_selftest bip44_canonical roundtrip e2e_test
)
