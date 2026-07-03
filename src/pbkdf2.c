/*
 * PBKDF2-HMAC-SHA512
 */
#include "pbkdf2.h"
#include "hmac_sha512.h"
#include <string.h>

static void F(const uint8_t *P, size_t Plen,
              const uint8_t *S, size_t Slen,
              uint32_t c, uint32_t i, uint8_t out[SHA512_DIGEST_LEN])
{
    if (Slen > 240) { memset(out, 0, SHA512_DIGEST_LEN); return; }

    uint8_t salt_plus_idx[256];
    memcpy(salt_plus_idx, S, Slen);
    salt_plus_idx[Slen+0] = (uint8_t)(i >> 24);
    salt_plus_idx[Slen+1] = (uint8_t)(i >> 16);
    salt_plus_idx[Slen+2] = (uint8_t)(i >> 8);
    salt_plus_idx[Slen+3] = (uint8_t)(i);

    uint8_t U[SHA512_DIGEST_LEN];
    hmac_sha512(P, Plen, salt_plus_idx, Slen + 4, U);
    memcpy(out, U, SHA512_DIGEST_LEN);
    for (uint32_t j = 1; j < c; j++) {
        uint8_t prev[SHA512_DIGEST_LEN];
        memcpy(prev, U, SHA512_DIGEST_LEN);
        hmac_sha512(P, Plen, prev, SHA512_DIGEST_LEN, U);
        for (int k = 0; k < SHA512_DIGEST_LEN; k++) out[k] ^= U[k];
    }
}

void pbkdf2_hmac_sha512(const uint8_t *pw, size_t pw_len,
                        const uint8_t *salt, size_t salt_len,
                        uint32_t iters,
                        uint8_t *out, size_t out_len)
{
    uint32_t blocks = (uint32_t)((out_len + SHA512_DIGEST_LEN - 1) / SHA512_DIGEST_LEN);
    for (uint32_t i = 1; i <= blocks; i++) {
        uint8_t blk[SHA512_DIGEST_LEN];
        F(pw, pw_len, salt, salt_len, iters, i, blk);
        size_t take = out_len - (size_t)(i-1) * SHA512_DIGEST_LEN;
        if (take > SHA512_DIGEST_LEN) take = SHA512_DIGEST_LEN;
        memcpy(out + (size_t)(i-1) * SHA512_DIGEST_LEN, blk, take);
    }
}
