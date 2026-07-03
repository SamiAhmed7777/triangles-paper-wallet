/*
 * SHA-512 + HMAC-SHA512 wrapper, OpenSSL 3.x EVP.
 */
#ifndef TRI_PAPER_HMAC_SHA512_H
#define TRI_PAPER_HMAC_SHA512_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>

#define SHA512_BLOCK_SIZE 128
#define SHA512_DIGEST_LEN 64

typedef struct {
    EVP_MD_CTX *mdctx;
    uint64_t    bytes;
} sha512_ctx;

typedef struct {
    EVP_MAC_CTX *macctx;
    /* unused fields kept for binary compatibility */
    void       *mac;
} hmac_sha512_ctx;

void sha512_init(sha512_ctx *c);
void sha512_update(sha512_ctx *c, const uint8_t *data, size_t len);
void sha512_final(sha512_ctx *c, uint8_t out[SHA512_DIGEST_LEN]);
void sha512(const uint8_t *data, size_t len, uint8_t out[SHA512_DIGEST_LEN]);

void hmac_sha512_init(hmac_sha512_ctx *c, const uint8_t *key, size_t key_len);
void hmac_sha512_update(hmac_sha512_ctx *c, const uint8_t *data, size_t len);
void hmac_sha512_final(hmac_sha512_ctx *c, uint8_t out[SHA512_DIGEST_LEN]);

void hmac_sha512(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out[SHA512_DIGEST_LEN]);

#endif
