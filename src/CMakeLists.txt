# triangles-paper-wallet/src/CMakeLists.txt
#
# Thin wrapper around vendored libsecp256k1. All other primitives
# (SHA-256, SHA-512, HMAC-SHA512, PBKDF2, RIPEMD-160, Base58) are
# small enough to vendor here without dragging in a separate library.

set(SRCS
    main.c
    entropy.c
    bip39.c
    pbkdf2.c
    hmac_sha512.c
    sha256.c
    ripemd160.c
    base58.c
    bip32.c
    bip44.c
    paper.c
    pdf.c
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

# Link against libsecp256k1 only. No other deps.
target_link_libraries(triangles-mint-paper-wallet PRIVATE
    secp256k1
)

# No-exec-stack + RELRO + bind-now
target_link_options(triangles-mint-paper-wallet PRIVATE
    "-Wl,--no-undefined"
    "-Wl,-z,relro"
    "-Wl,-z,now"
    "-Wl,-z,noexecstack"
    "-Wl,--as-needed"
)

install(TARGETS triangles-mint-paper-wallet
    RUNTIME DESTINATION bin
)
