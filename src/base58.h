/*
 * Base58Check encode/decode (Bitcoin alphabet).
 */
#ifndef TRI_PAPER_BASE58_H
#define TRI_PAPER_BASE58_H

#include <stdint.h>
#include <stddef.h>

int b58check_encode(const uint8_t *in, size_t in_len,
                    uint8_t *out, size_t *out_len);
int b58check_decode(const char *in,
                    uint8_t *out, size_t *out_len);

#endif
