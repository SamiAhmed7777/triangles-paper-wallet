// Copyright (c) 2014-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Transliterated from src/crypto/ripemd160.cpp @ bitcoin/bitcoin v29.0
// (https://github.com/bitcoin/bitcoin/blob/v29.0/src/crypto/ripemd160.cpp)
// by Krystie for the Triangles offline paper-wallet tool.
//
// This is a pure-C rewrite of Bitcoin Core's C++ RIPEMD-160 implementation.
// The cryptographic math is byte-for-byte identical to the upstream:
//   - f1..f5 round functions
//   - K constants: 0, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E
//                  0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0
//   - Round ordering (R11..R52) and shift amounts
//   - Dual parallel computation (1, 2), combined into the state with
//     t = s[0]; s[0] = s[1] + c1 + d2; ... ; s[4] = t + b1 + c2
//
// Endianness: state words are written to the output buffer in little-endian
// byte order (matches Bitcoin Core's WriteLE32 + OpenSSL RIPEMD160 output).
//
// Verifiable against openssl dgst -ripemd160 on any input.

#include "ripemd160.h"

#include <string.h>

/* ------------------------------------------------------------------ */
/* Internal helpers (Bitcoin Core namespace ripemd160)                */
/* ------------------------------------------------------------------ */

static inline uint32_t rotl32(uint32_t x, int i) {
    return (x << i) | (x >> (32 - i));
}

/* Round functions f1..f5 — identical to Bitcoin Core. */
static inline uint32_t f1(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
static inline uint32_t f2(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
static inline uint32_t f3(uint32_t x, uint32_t y, uint32_t z) { return (x | ~y) ^ z; }
static inline uint32_t f4(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); }
static inline uint32_t f5(uint32_t x, uint32_t y, uint32_t z) { return x ^ (y | ~z); }

/* Initial state. Bitcoin Core's Initialize(). */
static void initialize(uint32_t s[5]) {
    s[0] = 0x67452301UL;
    s[1] = 0xEFCDAB89UL;
    s[2] = 0x98BADCFEUL;
    s[3] = 0x10325476UL;
    s[4] = 0xC3D2E1F0UL;
}

/* Endian-neutral little-endian load/store on a uint32_t. */
static inline uint32_t read_le32(const unsigned char *p) {
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static inline void write_le32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v       & 0xff);
    p[1] = (unsigned char)((v >>  8) & 0xff);
    p[2] = (unsigned char)((v >> 16) & 0xff);
    p[3] = (unsigned char)((v >> 24) & 0xff);
}

static inline void write_le64(unsigned char *p, uint64_t v) {
    uint32_t lo = (uint32_t)(v & 0xffffffffULL);
    uint32_t hi = (uint32_t)(v >> 32);
    write_le32(p,     lo);
    write_le32(p + 4, hi);
}

/* Round macro — identical to Bitcoin Core's Round + Rxx helpers. */
#define TRI_ROUND(a, b, c, d, e, FN, x, k, r) do { \
        a = rotl32(a + (FN)(b, c, d) + (x) + (k), r) + (e); \
        c = rotl32(c, 10); \
    } while (0)

#define R11(a, b, c, d, e, x, r) TRI_ROUND(a, b, c, d, e, f1, x, 0UL,                r)
#define R21(a, b, c, d, e, x, r) TRI_ROUND(a, b, c, d, e, f2, x, 0x5A827999UL,     r)
#define R31(a, b, c, d, e, x, r) TRI_ROUND(a, b, c, d, e, f3, x, 0x6ED9EBA1UL,     r)
#define R41(a, b, c, d, e, x, r) TRI_ROUND(a, b, c, d, e, f4, x, 0x8F1BBCDCUL,     r)
#define R51(a, b, c, d, e, x, r) TRI_ROUND(a, b, c, d, e, f5, x, 0xA953FD4EUL,     r)
#define R12(a, b, c, d, e, x, r) TRI_ROUND(a, b, c, d, e, f5, x, 0x50A28BE6UL,     r)
#define R22(a, b, c, d, e, x, r) TRI_ROUND(a, b, c, d, e, f4, x, 0x5C4DD124UL,     r)
#define R32(a, b, c, d, e, x, r) TRI_ROUND(a, b, c, d, e, f3, x, 0x6D703EF3UL,     r)
#define R42(a, b, c, d, e, x, r) TRI_ROUND(a, b, c, d, e, f2, x, 0x7A6D76E9UL,     r)
#define R52(a, b, c, d, e, x, r) TRI_ROUND(a, b, c, d, e, f1, x, 0UL,                r)

/* Perform a RIPEMD-160 transformation on a 64-byte chunk.
   Byte-for-byte identical to Bitcoin Core's ripemd160::Transform(). */
static void transform(uint32_t s[5], const unsigned char chunk[64]) {
    uint32_t a1 = s[0], b1 = s[1], c1 = s[2], d1 = s[3], e1 = s[4];
    uint32_t a2 = a1,    b2 = b1,    c2 = c1,    d2 = d1,    e2 = e1;

    uint32_t w0  = read_le32(chunk +  0);
    uint32_t w1  = read_le32(chunk +  4);
    uint32_t w2  = read_le32(chunk +  8);
    uint32_t w3  = read_le32(chunk + 12);
    uint32_t w4  = read_le32(chunk + 16);
    uint32_t w5  = read_le32(chunk + 20);
    uint32_t w6  = read_le32(chunk + 24);
    uint32_t w7  = read_le32(chunk + 28);
    uint32_t w8  = read_le32(chunk + 32);
    uint32_t w9  = read_le32(chunk + 36);
    uint32_t w10 = read_le32(chunk + 40);
    uint32_t w11 = read_le32(chunk + 44);
    uint32_t w12 = read_le32(chunk + 48);
    uint32_t w13 = read_le32(chunk + 52);
    uint32_t w14 = read_le32(chunk + 56);
    uint32_t w15 = read_le32(chunk + 60);

    R11(a1, b1, c1, d1, e1, w0,  11);
    R12(a2, b2, c2, d2, e2, w5,   8);
    R11(e1, a1, b1, c1, d1, w1,  14);
    R12(e2, a2, b2, c2, d2, w14,  9);
    R11(d1, e1, a1, b1, c1, w2,  15);
    R12(d2, e2, a2, b2, c2, w7,   9);
    R11(c1, d1, e1, a1, b1, w3,  12);
    R12(c2, d2, e2, a2, b2, w0,  11);
    R11(b1, c1, d1, e1, a1, w4,   5);
    R12(b2, c2, d2, e2, a2, w9,  13);
    R11(a1, b1, c1, d1, e1, w5,   8);
    R12(a2, b2, c2, d2, e2, w2,  15);
    R11(e1, a1, b1, c1, d1, w6,   7);
    R12(e2, a2, b2, c2, d2, w11, 15);
    R11(d1, e1, a1, b1, c1, w7,   9);
    R12(d2, e2, a2, b2, c2, w4,   5);
    R11(c1, d1, e1, a1, b1, w8,  11);
    R12(c2, d2, e2, a2, b2, w13,  7);
    R11(b1, c1, d1, e1, a1, w9,  13);
    R12(b2, c2, d2, e2, a2, w6,   7);
    R11(a1, b1, c1, d1, e1, w10, 14);
    R12(a2, b2, c2, d2, e2, w15,  8);
    R11(e1, a1, b1, c1, d1, w11, 15);
    R12(e2, a2, b2, c2, d2, w8,  11);
    R11(d1, e1, a1, b1, c1, w12,  6);
    R12(d2, e2, a2, b2, c2, w1,  14);
    R11(c1, d1, e1, a1, b1, w13,  7);
    R12(c2, d2, e2, a2, b2, w10, 14);
    R11(b1, c1, d1, e1, a1, w14,  9);
    R12(b2, c2, d2, e2, a2, w3,  12);
    R11(a1, b1, c1, d1, e1, w15,  8);
    R12(a2, b2, c2, d2, e2, w12,  6);

    R21(e1, a1, b1, c1, d1, w7,   7);
    R22(e2, a2, b2, c2, d2, w6,   9);
    R21(d1, e1, a1, b1, c1, w4,   6);
    R22(d2, e2, a2, b2, c2, w11, 13);
    R21(c1, d1, e1, a1, b1, w13,  8);
    R22(c2, d2, e2, a2, b2, w3,  15);
    R21(b1, c1, d1, e1, a1, w1,  13);
    R22(b2, c2, d2, e2, a2, w7,   7);
    R21(a1, b1, c1, d1, e1, w10, 11);
    R22(a2, b2, c2, d2, e2, w0,  12);
    R21(e1, a1, b1, c1, d1, w6,   9);
    R22(e2, a2, b2, c2, d2, w13,  8);
    R21(d1, e1, a1, b1, c1, w15,  7);
    R22(d2, e2, a2, b2, c2, w5,   9);
    R21(c1, d1, e1, a1, b1, w3,  15);
    R22(c2, d2, e2, a2, b2, w10, 11);
    R21(b1, c1, d1, e1, a1, w12,  7);
    R22(b2, c2, d2, e2, a2, w14,  7);
    R21(a1, b1, c1, d1, e1, w0,  12);
    R22(a2, b2, c2, d2, e2, w15,  7);
    R21(e1, a1, b1, c1, d1, w9,  15);
    R22(e2, a2, b2, c2, d2, w8,  12);
    R21(d1, e1, a1, b1, c1, w5,   9);
    R22(d2, e2, a2, b2, c2, w12,  7);
    R21(c1, d1, e1, a1, b1, w2,  11);
    R22(c2, d2, e2, a2, b2, w4,   6);
    R21(b1, c1, d1, e1, a1, w14,  7);
    R22(b2, c2, d2, e2, a2, w9,  15);
    R21(a1, b1, c1, d1, e1, w11, 13);
    R22(a2, b2, c2, d2, e2, w1,  13);
    R21(e1, a1, b1, c1, d1, w8,  12);
    R22(e2, a2, b2, c2, d2, w2,  11);

    R31(d1, e1, a1, b1, c1, w3,  11);
    R32(d2, e2, a2, b2, c2, w15,  9);
    R31(c1, d1, e1, a1, b1, w10, 13);
    R32(c2, d2, e2, a2, b2, w5,   7);
    R31(b1, c1, d1, e1, a1, w14,  6);
    R32(b2, c2, d2, e2, a2, w1,  15);
    R31(a1, b1, c1, d1, e1, w4,   7);
    R32(a2, b2, c2, d2, e2, w3, 11);
    R31(e1, a1, b1, c1, d1, w9,  14);
    R32(e2, a2, b2, c2, d2, w7,   8);
    R31(d1, e1, a1, b1, c1, w15,  9);
    R32(d2, e2, a2, b2, c2, w14,  6);
    R31(c1, d1, e1, a1, b1, w8,  13);
    R32(c2, d2, e2, a2, b2, w6,   6);
    R31(b1, c1, d1, e1, a1, w1,  15);
    R32(b2, c2, d2, e2, a2, w9,  14);
    R31(a1, b1, c1, d1, e1, w2,  14);
    R32(a2, b2, c2, d2, e2, w11, 12);
    R31(e1, a1, b1, c1, d1, w7,   8);
    R32(e2, a2, b2, c2, d2, w8,  13);
    R31(d1, e1, a1, b1, c1, w0,  13);
    R32(d2, e2, a2, b2, c2, w12,  5);
    R31(c1, d1, e1, a1, b1, w6,   6);
    R32(c2, d2, e2, a2, b2, w2,  14);
    R31(b1, c1, d1, e1, a1, w13,  5);
    R32(b2, c2, d2, e2, a2, w10, 13);
    R31(a1, b1, c1, d1, e1, w11, 12);
    R32(a2, b2, c2, d2, e2, w0,  13);
    R31(e1, a1, b1, c1, d1, w5,   7);
    R32(e2, a2, b2, c2, d2, w4,   7);
    R31(d1, e1, a1, b1, c1, w12,  5);
    R32(d2, e2, a2, b2, c2, w13,  5);

    R41(c1, d1, e1, a1, b1, w1,  11);
    R42(c2, d2, e2, a2, b2, w8,  15);
    R41(b1, c1, d1, e1, a1, w9,  12);
    R42(b2, c2, d2, e2, a2, w6,   5);
    R41(a1, b1, c1, d1, e1, w11, 14);
    R42(a2, b2, c2, d2, e2, w4,   8);
    R41(e1, a1, b1, c1, d1, w10, 15);
    R42(e2, a2, b2, c2, d2, w1,  11);
    R41(d1, e1, a1, b1, c1, w0,  14);
    R42(d2, e2, a2, b2, c2, w3,  14);
    R41(c1, d1, e1, a1, b1, w8,  15);
    R42(c2, d2, e2, a2, b2, w11, 14);
    R41(b1, c1, d1, e1, a1, w12,  9);
    R42(b2, c2, d2, e2, a2, w15,  6);
    R41(a1, b1, c1, d1, e1, w4,   8);
    R42(a2, b2, c2, d2, e2, w0,  14);
    R41(e1, a1, b1, c1, d1, w13,  9);
    R42(e2, a2, b2, c2, d2, w5,   6);
    R41(d1, e1, a1, b1, c1, w3,  14);
    R42(d2, e2, a2, b2, c2, w12,  9);
    R41(c1, d1, e1, a1, b1, w7,   5);
    R42(c2, d2, e2, a2, b2, w2,  12);
    R41(b1, c1, d1, e1, a1, w15,  6);
    R42(b2, c2, d2, e2, a2, w13,  9);
    R41(a1, b1, c1, d1, e1, w14,  8);
    R42(a2, b2, c2, d2, e2, w9,  12);
    R41(e1, a1, b1, c1, d1, w5,   6);
    R42(e2, a2, b2, c2, d2, w7,   5);
    R41(d1, e1, a1, b1, c1, w6,   5);
    R42(d2, e2, a2, b2, c2, w10, 15);
    R41(c1, d1, e1, a1, b1, w2,  12);
    R42(c2, d2, e2, a2, b2, w14,  8);

    R51(b1, c1, d1, e1, a1, w4,   9);
    R52(b2, c2, d2, e2, a2, w12,  8);
    R51(a1, b1, c1, d1, e1, w0,  15);
    R52(a2, b2, c2, d2, e2, w15,  5);
    R51(e1, a1, b1, c1, d1, w5,   5);
    R52(e2, a2, b2, c2, d2, w10, 12);
    R51(d1, e1, a1, b1, c1, w9,  11);
    R52(d2, e2, a2, b2, c2, w4,   9);
    R51(c1, d1, e1, a1, b1, w7,   6);
    R52(c2, d2, e2, a2, b2, w1,  12);
    R51(b1, c1, d1, e1, a1, w12,  8);
    R52(b2, c2, d2, e2, a2, w5,   5);
    R51(a1, b1, c1, d1, e1, w2,  13);
    R52(a2, b2, c2, d2, e2, w8,  14);
    R51(e1, a1, b1, c1, d1, w10, 12);
    R52(e2, a2, b2, c2, d2, w7,   6);
    R51(d1, e1, a1, b1, c1, w14,  5);
    R52(d2, e2, a2, b2, c2, w6,   8);
    R51(c1, d1, e1, a1, b1, w1,  12);
    R52(c2, d2, e2, a2, b2, w2,  13);
    R51(b1, c1, d1, e1, a1, w3,  13);
    R52(b2, c2, d2, e2, a2, w13,  6);
    R51(a1, b1, c1, d1, e1, w8,  14);
    R52(a2, b2, c2, d2, e2, w14,  5);
    R51(e1, a1, b1, c1, d1, w11, 11);
    R52(e2, a2, b2, c2, d2, w0,  15);
    R51(d1, e1, a1, b1, c1, w6,   8);
    R52(d2, e2, a2, b2, c2, w3,  13);
    R51(c1, d1, e1, a1, b1, w15,  5);
    R52(c2, d2, e2, a2, b2, w9,  11);
    R51(b1, c1, d1, e1, a1, w13,  6);
    R52(b2, c2, d2, e2, a2, w11, 11);

    uint32_t t = s[0];
    s[0] = s[1] + c1 + d2;
    s[1] = s[2] + d1 + e2;
    s[2] = s[3] + e1 + a2;
    s[3] = s[4] + a1 + b2;
    s[4] = t     + b1 + c2;
}

/* ------------------------------------------------------------------ */
/* Streaming API                                                       */
/* ------------------------------------------------------------------ */

void tri_ripemd160_init(tri_ripemd160_ctx *ctx) {
    initialize(ctx->s);
    ctx->bytes = 0;
}

void tri_ripemd160_update(tri_ripemd160_ctx *ctx,
                          const unsigned char *data, size_t len) {
    const unsigned char *end = data + len;
    size_t bufsize = (size_t)(ctx->bytes % TRI_RIPEMD160_BLOCK_SIZE);

    if (bufsize && bufsize + len >= TRI_RIPEMD160_BLOCK_SIZE) {
        /* Fill the buffer and process it. */
        size_t fill = TRI_RIPEMD160_BLOCK_SIZE - bufsize;
        memcpy(ctx->buf + bufsize, data, fill);
        ctx->bytes += fill;
        data += fill;
        transform(ctx->s, ctx->buf);
        bufsize = 0;
    }

    while (end - data >= TRI_RIPEMD160_BLOCK_SIZE) {
        transform(ctx->s, data);
        ctx->bytes += TRI_RIPEMD160_BLOCK_SIZE;
        data += TRI_RIPEMD160_BLOCK_SIZE;
    }

    if (end > data) {
        size_t remaining = (size_t)(end - data);
        memcpy(ctx->buf + bufsize, data, remaining);
        ctx->bytes += remaining;
    }
}

void tri_ripemd160_final(tri_ripemd160_ctx *ctx,
                         unsigned char out[TRI_RIPEMD160_OUTPUT_SIZE]) {
    static const unsigned char pad[64] = {0x80};
    unsigned char sizedesc[8];
    uint64_t total_bits;

    /* CRITICAL: capture total input length BEFORE the pad write advances
       ctx->bytes. Bitcoin Core's CRIPEMD160::Finalize does the same. */
    total_bits = (uint64_t)ctx->bytes << 3;

    /* Zero-pad in the SHA-style: 0x80 then zeros until 8 bytes short. */
    size_t pad_len = 1 + ((119 - (size_t)(ctx->bytes % TRI_RIPEMD160_BLOCK_SIZE)) % 64);
    tri_ripemd160_update(ctx, pad, pad_len);

    write_le64(sizedesc, total_bits);
    tri_ripemd160_update(ctx, sizedesc, 8);

    write_le32(out +  0, ctx->s[0]);
    write_le32(out +  4, ctx->s[1]);
    write_le32(out +  8, ctx->s[2]);
    write_le32(out + 12, ctx->s[3]);
    write_le32(out + 16, ctx->s[4]);
}

void tri_ripemd160(const unsigned char *data, size_t len,
                   unsigned char out[TRI_RIPEMD160_OUTPUT_SIZE]) {
    tri_ripemd160_ctx ctx;
    tri_ripemd160_init(&ctx);
    tri_ripemd160_update(&ctx, data, len);
    tri_ripemd160_final(&ctx, out);
}
