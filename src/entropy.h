/*
 * entropy.h — OS CSPRNG wrapper for BIP39 initial entropy.
 *
 * Tries getrandom() first (Linux 3.17+), falls back to /dev/urandom.
 * We do NOT use rand(), srand(), time(), or any userland source.
 */
#ifndef TRI_PAPER_ENTROPY_H
#define TRI_PAPER_ENTROPY_H

#include <stdint.h>
#include <stddef.h>

/* Returns 0 on success, -1 on failure. */
int get_crypto_entropy(uint8_t *out, size_t len);

#endif
