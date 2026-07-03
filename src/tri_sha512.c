/*
 * SHA-512 + HMAC-SHA512 thin wrapper over OpenSSL 3.x EVP.
 */
#include "hmac_sha512.h"
#include <string.h>
#include <openssl/evp.h>

void sha512_init(sha512_ctx *c) {
    c->mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(c->mdctx, EVP_sha512(), NULL);
    c->bytes = 0;
}

void sha512_update(sha512_ctx *c, const unsigned char *data, size_t len) {
    EVP_DigestUpdate(c->mdctx, data, len);
    c->bytes += len;
}

void sha512_final(sha512_ctx *c, unsigned char out[SHA512_DIGEST_LEN]) {
    unsigned int outlen = 0;
    EVP_DigestFinal_ex(c->mdctx, out, &outlen);
    EVP_MD_CTX_free(c->mdctx);
    c->mdctx = NULL;
}

void sha512(const unsigned char *data, size_t len, unsigned char out[SHA512_DIGEST_LEN]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    unsigned int outlen = 0;
    EVP_DigestFinal_ex(ctx, out, &outlen);
    EVP_MD_CTX_free(ctx);
}

void hmac_sha512_init(hmac_sha512_ctx *c, const unsigned char *key, size_t key_len) {
    c->macctx = EVP_MAC_CTX_new(EVP_MAC_fetch(NULL, "HMAC", NULL));
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA512", 0);
    params[1] = OSSL_PARAM_construct_end();
    EVP_MAC_init(c->macctx, key, key_len, params);
}

void hmac_sha512_update(hmac_sha512_ctx *c, const unsigned char *data, size_t len) {
    EVP_MAC_update(c->macctx, data, len);
}

void hmac_sha512_final(hmac_sha512_ctx *c, unsigned char out[SHA512_DIGEST_LEN]) {
    size_t outlen = 0;
    EVP_MAC_final(c->macctx, out, &outlen, SHA512_DIGEST_LEN);
    EVP_MAC_CTX_free(c->macctx);
    c->macctx = NULL;
}

void hmac_sha512(const unsigned char *key, size_t key_len,
                 const unsigned char *data, size_t data_len,
                 unsigned char out[SHA512_DIGEST_LEN]) {
    hmac_sha512_ctx c;
    hmac_sha512_init(&c, key, key_len);
    hmac_sha512_update(&c, data, data_len);
    hmac_sha512_final(&c, out);
}
