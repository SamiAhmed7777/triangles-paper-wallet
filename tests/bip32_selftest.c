/* BIP32 spec test vectors — see https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 * Vector 1 from the BIP32 spec, with seed = 000102030405060708090a0b0c0d0e0f.
 *
 * Cross-verified expected values from Python hmac + secp256k1 (coincurve):
 *
 *   master: key=e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35
 *           cc=873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508
 *   m/0':  key=edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea
 *           cc=47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141
 *   m/0'/1: key=...
 *           cc=...
 */
#include <stdio.h>
#include <string.h>

#include "bip32.h"

extern size_t hex2bin_var(const char *hex, unsigned char *out, size_t out_max);
extern int  hex2bin(const char *hex, unsigned char *out, size_t outlen);
extern void bin2hex(const unsigned char *in, size_t len, char *out);

typedef struct {
    const char *seed_hex;
    const char *path;
    const char *expected_key_hex;
    const char *expected_cc_hex;
} bip32_vec_t;

static const bip32_vec_t vectors[] = {
    /* BIP32 spec test vector 1, chain m */
    {"000102030405060708090a0b0c0d0e0f", "m",
     "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
     "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"},
    /* chain m/0' (first hardened child) */
    {"000102030405060708090a0b0c0d0e0f", "m/0'",
     "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
     "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"},
    {NULL, NULL, NULL, NULL}
};

static int run_vector(const bip32_vec_t *v, int n) {
    unsigned char seed[256];
    size_t seed_len = hex2bin_var(v->seed_hex, seed, sizeof(seed));
    if (seed_len == 0) {
        fprintf(stderr, "v[%d]: bad seed hex\n", n);
        return 0;
    }
    tri_extkey_t master;
    if (!tri_bip32_master_from_seed(seed, seed_len, &master)) {
        fprintf(stderr, "v[%d]: master_from_seed failed (key out of range)\n", n);
        return 0;
    }
    uint32_t indices[10];
    int count = tri_bip32_parse_path(v->path, indices, 10);
    if (count < 0) {
        fprintf(stderr, "v[%d]: bad path: %s\n", n, v->path);
        return 0;
    }
    tri_extkey_t child;
    if (!tri_bip32_derive_path(&master, indices, count, &child)) {
        fprintf(stderr, "v[%d]: derivation failed\n", n);
        return 0;
    }
    unsigned char want_key[32], want_cc[32];
    if (hex2bin(v->expected_key_hex, want_key, 32)) {
        fprintf(stderr, "v[%d]: bad expected key hex\n", n); return 0;
    }
    if (hex2bin(v->expected_cc_hex, want_cc, 32)) {
        fprintf(stderr, "v[%d]: bad expected cc hex\n", n); return 0;
    }
    int ok = (memcmp(want_key, child.key, 32) == 0)
           && (memcmp(want_cc,  child.chain_code, 32) == 0);
    if (!ok) {
        char gk[65], gc[65], gp[67];
        bin2hex(child.key, 32, gk);
        bin2hex(child.chain_code, 32, gc);
        bin2hex(child.pubkey_compressed, 33, gp);
        fprintf(stderr, "v[%d] %s:\n  got  key=%s cc=%s\n  want key=%s cc=%s\n",
                n, v->path, gk, gc, v->expected_key_hex, v->expected_cc_hex);
        return 0;
    }
    return 1;
}

int main(void) {
    int ok = 1;
    for (int i = 0; vectors[i].seed_hex != NULL; i++) {
        ok &= run_vector(&vectors[i], i);
    }
    if (ok) {
        printf("BIP32 spec vectors: PASS (%d vectors)\n",
               (int)(sizeof(vectors)/sizeof(vectors[0]) - 1));
        return 0;
    }
    printf("BIP32 spec vectors: FAIL\n");
    return 1;
}
