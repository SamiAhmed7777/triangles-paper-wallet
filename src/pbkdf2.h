/*
 * PBKDF2-HMAC-SHA512 — RFC 8018.
 * Used by BIP39 (2048 iterations).
 */
#ifndef TRI_PAPER_PBKDF2_H
#define TRI_PAPER_PBKDF2_H

#include <stdint.h>
#include <stddef.h>

void pbkdf2_hmac_sha512(const uint8_t *pw, size_t pw_len,
                        const uint8_t *salt, size_t salt_len,
                        uint32_t iters,
                        uint8_t *out, size_t out_len);

#endif
