/*
 * BIP32 implementation. See bip32.h for the API contract.
 *
 *   MasterFromSeed(seed):
 *     I = HMAC-SHA512(Key="Bitcoin seed", Data=seed)
 *     IL = I[0..32]  -> master private key
 *     IR = I[32..64] -> master chain code
 *
 *   CKDpriv((k_par, c_par), i):
 *     if hardened (i >= 2^31):
 *        I = HMAC-SHA512(Key=c_par, Data=0x00||ser256(k_par)||ser256(i))
 *     else:
 *        I = HMAC-SHA512(Key=c_par, Data=serP(point(k_par))||ser256(i))
 *     IL = I[0..32]; IR = I[32..64]
 *     child_key = (IL + k_par) mod n
 *     if child_key == 0: invalid, try next i
 *
 *   fingerprint(k) = first 4 bytes of RIPEMD-160(SHA-256(compressed_pubkey))
 *
 * All EC math uses the PUBLIC libsecp256k1 API (secp256k1_ec_pubkey_*).
 * The submodule's scalar API is internal-only and not exposed.
 */

#include "bip32.h"

#include <string.h>

#include "ripemd160.h"
#include "sha256.h"
#include "hmac_sha512.h"

#include <secp256k1.h>

/* ---- internal helpers -------------------------------------------------- */

static int compute_pubkey_compressed(const secp256k1_context *ctx,
                                     const uint8_t seckey[32],
                                     uint8_t compressed_out[33])
{
    secp256k1_pubkey pk;
    if (!secp256k1_ec_seckey_verify(ctx, seckey)) {
        return 0;
    }
    if (!secp256k1_ec_pubkey_create(ctx, &pk, seckey)) {
        return 0;
    }
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, compressed_out, &len, &pk,
                                  SECP256K1_EC_COMPRESSED);
    return (len == 33) ? 1 : 0;
}

/* ---- master generation ------------------------------------------------ */
int tri_bip32_master_from_seed(const uint8_t *seed, size_t seed_len, tri_extkey_t *out)
{
    static const uint8_t key_word[] = {'B','i','t','c','o','i','n',' ',
                                        's','e','e','d'}; /* "Bitcoin seed" */
    uint8_t I[64];

    /* HMAC-SHA512(key=key_word, msg=seed) -> I */
    hmac_sha512(key_word, sizeof(key_word), seed, seed_len, I);

    memcpy(out->key, I, 32);
    memcpy(out->chain_code, I + 32, 32);
    out->depth = 0;
    out->child_number = 0;
    memset(out->parent_fingerprint, 0, 4);
    out->pubkey_compressed[0] = 0;  /* mark invalid until computed */

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    int ok = compute_pubkey_compressed(ctx, out->key, out->pubkey_compressed);
    secp256k1_context_destroy(ctx);
    return ok;
}

/* ---- child key derivation (CKDpriv) ----------------------------------- */
int tri_bip32_ckd_priv(tri_extkey_t *parent, uint32_t i, tri_extkey_t *out)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    uint8_t data[37];
    size_t  data_len;
    uint8_t I[64];

    if (i >= BIP32_HARDENED) {
        /* Hardened: data = 0x00 || ser256(parent_key) || ser32(i) */
        data[0] = 0x00;
        memcpy(data + 1, parent->key, 32);
        data[33] = (uint8_t)((i >> 24) & 0xff);
        data[34] = (uint8_t)((i >> 16) & 0xff);
        data[35] = (uint8_t)((i >>  8) & 0xff);
        data[36] = (uint8_t)( i        & 0xff);
        data_len = 37;
    } else {
        /* Non-hardened: data = serP(point(parent_key)) || ser32(i) */
        memcpy(data, parent->pubkey_compressed, 33);
        data[33] = (uint8_t)((i >> 24) & 0xff);
        data[34] = (uint8_t)((i >> 16) & 0xff);
        data[35] = (uint8_t)((i >>  8) & 0xff);
        data[36] = (uint8_t)( i        & 0xff);
        data_len = 37;
    }

    hmac_sha512(parent->chain_code, 32, data, data_len, I);
    memcpy(out->chain_code, I + 32, 32);

    /* child_key = (IL + parent_key) mod n.
     * secp256k1_ec_seckey_tweak_add performs add-mod-n and rejects overflow
     * by zeroing the result (it returns 0 in that case).
     */
    memcpy(out->key, parent->key, 32);
    if (!secp256k1_ec_seckey_tweak_add(ctx, out->key, I /* IL */)) {
        /* Invalid (would be zero or >= n). Per BIP32, try next i. Report fail. */
        secp256k1_context_destroy(ctx);
        return 0;
    }
    if (!secp256k1_ec_seckey_verify(ctx, out->key)) {
        secp256k1_context_destroy(ctx);
        return 0;
    }

    /* Derive parent pubkey, then tweak by IL to get child pubkey. */
    secp256k1_pubkey parent_pk, child_pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &parent_pk, parent->pubkey_compressed, 33)) {
        secp256k1_context_destroy(ctx);
        return 0;
    }
    if (i >= BIP32_HARDENED) {
        /* For hardened derivation we don't have a parent pubkey that the BIP32
         * algorithm uses to compute the child. We must derive the child pubkey
         * directly from the child key. */
        if (!secp256k1_ec_pubkey_create(ctx, &child_pk, out->key)) {
            secp256k1_context_destroy(ctx);
            return 0;
        }
    } else {
        memcpy(&child_pk, &parent_pk, sizeof(child_pk));
        if (!secp256k1_ec_pubkey_tweak_add(ctx, &child_pk, I /* IL */)) {
            secp256k1_context_destroy(ctx);
            return 0;
        }
    }
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, out->pubkey_compressed, &len, &child_pk,
                                  SECP256K1_EC_COMPRESSED);
    if (len != 33) {
        secp256k1_context_destroy(ctx);
        return 0;
    }

    out->depth = parent->depth + 1;
    out->child_number = i;
    tri_bip32_fingerprint(parent, out->parent_fingerprint);

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- path walking ----------------------------------------------------- */
int tri_bip32_parse_path(const char *path, uint32_t *indices, size_t max)
{
    if (!path || !indices || max == 0) return -1;
    if (path[0] != 'm' && path[0] != 'M') return -1;
    size_t pos = 1;
    size_t n = 0;

    if (path[pos] == '\0') return 0;

    while (path[pos] != '\0') {
        if (path[pos] != '/') return -1;
        pos++;
        int hardened = 0;
        if (path[pos] == '\'') { hardened = 1; pos++; }
        if (path[pos] < '0' || path[pos] > '9') return -1;
        uint32_t v = 0;
        while (path[pos] >= '0' && path[pos] <= '9') {
            v = v * 10u + (uint32_t)(path[pos] - '0');
            pos++;
        }
        if (path[pos] == '\'') {
            hardened = 1;
            pos++;
        }
        if (n >= max) return -1;
        if (hardened) v |= BIP32_HARDENED;
        indices[n++] = v;
    }
    return (int)n;
}

int tri_bip32_derive_path(const tri_extkey_t *master, const uint32_t *indices, size_t n,
                          tri_extkey_t *out)
{
    tri_extkey_t cur, next;
    memcpy(&cur, master, sizeof(cur));
    for (size_t i = 0; i < n; i++) {
        if (!tri_bip32_ckd_priv(&cur, indices[i], &next)) return 0;
        cur = next;
    }
    memcpy(out, &cur, sizeof(*out));
    return 1;
}

/* ---- fingerprint ------------------------------------------------------ */
void tri_bip32_fingerprint(const tri_extkey_t *key, uint8_t out[4])
{
    uint8_t sha[32], ripe[20];
    sha256(key->pubkey_compressed, 33, sha);
    tri_ripemd160(sha, 32, ripe);
    memcpy(out, ripe, 4);
}
