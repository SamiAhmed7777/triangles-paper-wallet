// Copyright (c) 2014-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Transliterated from src/crypto/ripemd160.cpp @ bitcoin/bitcoin v29.0
// by Krystie for the Triangles offline paper-wallet tool.
// Pure C rewrite of Bitcoin Core's C++ implementation.
// Math is byte-for-byte identical to the upstream implementation
// (round constants f1..f5, round order, K1..K5, mixing, endianness).

#ifndef TRI_RIPEMD160_H
#define TRI_RIPEMD160_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TRI_RIPEMD160_BLOCK_SIZE 64
#define TRI_RIPEMD160_OUTPUT_SIZE 20

typedef struct {
    uint32_t s[5];
    uint64_t bytes;
    unsigned char buf[TRI_RIPEMD160_BLOCK_SIZE];
} tri_ripemd160_ctx;

void tri_ripemd160_init(tri_ripemd160_ctx *ctx);
void tri_ripemd160_update(tri_ripemd160_ctx *ctx, const unsigned char *data, size_t len);
void tri_ripemd160_final(tri_ripemd160_ctx *ctx, unsigned char out[TRI_RIPEMD160_OUTPUT_SIZE]);
void tri_ripemd160(const unsigned char *data, size_t len, unsigned char out[TRI_RIPEMD160_OUTPUT_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* TRI_RIPEMD160_H */
