/*
 * BIP32 (Hierarchical Deterministic Wallets) — implements Master key generation,
 * CKDpriv (Child Key Derivation, private) for non-hardened and hardened paths.
 *
 * Uses libsecp256k1 for all elliptic-curve math. HMAC-SHA512 is provided by
 * src/tri_sha512.c (OpenSSL EVP wrapper).
 *
 * Path syntax (default):
 *   m / 44' / 2222' / 0' / 0 / i       (BIP44, Triangles coin_type=2222)
 *
 * The derived private key is a 32-byte big-endian secp256k1 scalar; the derived
 * chain code is 32 bytes. Together they constitute an "extended key" matching
 * the structure used by the daemon's MasterFromSeed() in src/hdwallet.cpp.
 */
#ifndef TRI_BIP32_H
#define TRI_BIP32_H

#include <stddef.h>
#include <stdint.h>

#define BIP32_HARDENED        ((uint32_t)0x80000000)
#define BIP32_MAX_DEPTH       255

typedef struct {
    /* depth: 0 for master, 1 for first child, etc. */
    uint8_t  depth;
    /* child_number: index of this key in its parent; 0 for master. */
    uint32_t child_number;
    /* chain_code: 32 bytes (BIP32 chain code) */
    uint8_t  chain_code[32];
    /* key: 32 bytes private key (big-endian secp256k1 scalar) */
    uint8_t  key[32];
    /* pubkey: 33-byte compressed (33 bytes for compat with secp256k1_ec_pubkey_serialize) */
    uint8_t  pubkey_compressed[33];
    /* parent fingerprint: 4 bytes (RIPEMD-160 of parent's pubkey, first 4 bytes) */
    uint8_t  parent_fingerprint[4];
} tri_extkey_t;

/*
 * Derive master key from BIP39 seed.
 * The seed is BIP39's 64-byte output (PBKDF2[mnemonic, "mnemonic"+pass,
 * 2048, HMAC-SHA512, 64]). Per BIP32 the input is consumed raw, of any
 * practical length from 16 to 64 bytes.
 * Returns 1 on success, 0 on failure.
 */
int tri_bip32_master_from_seed(const uint8_t *seed, size_t seed_len, tri_extkey_t *out);

/*
 * Derive child key at index i from parent.
 * If i >= BIP32_HARDENED, performs HARDENED derivation (uses parent private key).
 * Otherwise, performs NON-HARDENED derivation (uses parent compressed pubkey + parent chain code).
 * Returns 1 on success, 0 on failure.
 */
int tri_bip32_ckd_priv(tri_extkey_t *parent, uint32_t i, tri_extkey_t *out);

/*
 * BIP44 path parser: "m/44'/2222'/0'/0/0"
 * path: null-terminated string like "m/44'/2222'/0'/0/5"
 * indices: caller-allocated array of uint32_t, returned filled. Hardened flagged
 *          via the BIP32_HARDENED bit in each entry.
 * max: capacity of indices
 * Returns number of indices parsed (>=0) on success, -1 on parse error.
 */
int tri_bip32_parse_path(const char *path, uint32_t *indices, size_t max);

/*
 * Derive an extended key by walking a BIP32 path starting from master.
 * Returns 1 on success, 0 on failure.
 */
int tri_bip32_derive_path(const tri_extkey_t *master, const uint32_t *indices, size_t n,
                          tri_extkey_t *out);

/* Compute RIPEMD-160 of compressed pubkey, return first 4 bytes (fingerprint). */
void tri_bip32_fingerprint(const tri_extkey_t *key, uint8_t out[4]);

#endif
