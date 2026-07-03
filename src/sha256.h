/*
 * SHA-256 — FIPS 180-4 reference implementation.
 * Public domain.
 */
#ifndef TRI_PAPER_SHA256_H
#define TRI_PAPER_SHA256_H

#include <stdint.h>
#include <stddef.h>

#define SHA256_DIGEST_LEN 32

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buf[64];
    size_t   buflen;
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx *c, uint8_t out[SHA256_DIGEST_LEN]);
void sha256(const uint8_t *data, size_t len, uint8_t out[SHA256_DIGEST_LEN]);

#endif
