/* BIP44 + Triangles address test against canonical values.
 *
 * Reference values computed with Python (hmac + ecdsa.SECP256k1) for
 *   seed = 000102030405060708090a0b0c0d0e0f
 *   path = m/44'/2222'/0'/0/i, i = 0..4
 *
 * Expected addresses (Base58Check-encoded with version byte 0x41):
 *   m/44'/2222'/0'/0/0 = TX2CtXLrumG67GdyxY5EzC5pMxNDvCrSvX
 *   m/44'/2222'/0'/0/1 = TWw5xNrxxo9Rscpt1CMvcpWaN97Dx4CDhm
 *   m/44'/2222'/0'/0/2 = TQrMfsam2MzW7bzFP6KwokBWTpU3EJgMbB
 */
#include <stdio.h>
#include <string.h>
#include "bip32.h"
#include "bip44.h"

extern size_t hex2bin_var(const char *hex, unsigned char *out, size_t out_max);

static const char *expected_addrs[] = {
    "TX2CtXLrumG67GdyxY5EzC5pMxNDvCrSvX", /* index 0 */
    "TWw5xNrxxo9Rscpt1CMvcpWaN97Dx4CDhm", /* index 1 */
    "TQrMfsam2MzW7bzFP6KwokBWTpU3EJgMbB", /* index 2 */
    NULL
};

int main(void) {
    const char *seed_hex = "000102030405060708090a0b0c0d0e0f";
    unsigned char seed[256];
    size_t sl = hex2bin_var(seed_hex, seed, sizeof(seed));
    tri_extkey_t master;
    if (!tri_bip32_master_from_seed(seed, sl, &master)) return 1;

    int ok = 1;
    for (int i = 0; expected_addrs[i] != NULL; i++) {
        uint8_t addr[64] = {0};
        if (!tri_derive_triangles_addr(&master, 0, 0, (uint32_t)i, addr, sizeof(addr))) {
            fprintf(stderr, "derive failed for index %d\n", i); return 1;
        }
        if (memcmp(addr, expected_addrs[i], strlen(expected_addrs[i])) != 0) {
            fprintf(stderr, "addr %d mismatch:\n  got  '%s'\n  want '%s'\n",
                    i, (char *)addr, expected_addrs[i]);
            ok = 0;
        }
    }
    if (ok) {
        printf("BIP44 first 3 addresses: PASS\n");
        return 0;
    }
    printf("BIP44 first 3 addresses: FAIL\n");
    return 1;
}
