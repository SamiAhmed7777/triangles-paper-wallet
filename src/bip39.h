/*
 * BIP39 — Mnemonic code for generating deterministic keys.
 *
 * Reference: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 *
 * This module only generates mnemonics from external entropy.
 * It does NOT validate existing mnemonics in this minimal impl, but
 * mnemonic_to_seed() does PBKDF2 derivation as specified.
 */
#ifndef TRI_PAPER_BIP39_H
#define TRI_PAPER_BIP39_H

#include <stdint.h>
#include <stddef.h>

/* Generate a 12- or 24-word mnemonic from internal OS entropy.
 * Returns 0 on success. The mnemonic is space-separated words in 'out'. */
int bip39_generate(int n_words, char *out, size_t out_len);

/* Convert a mnemonic to a 64-byte BIP39 seed via PBKDF2-HMAC-SHA512.
 * mnemonic_passphrase is the optional "25th word" (NULL/"" = none). */
int bip39_mnemonic_to_seed(const char *mnemonic,
                           const char *passphrase,
                           uint8_t seed[64]);

#endif
