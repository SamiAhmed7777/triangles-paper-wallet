/* Round-trip test against canonical PBKDF2 + BIP39 + BIP32 + BIP44.
 *
 * Reference values all verified using:
 *   - Python (PBKDF2 via hashlib + HMAC + EC via ecdsa library) for BIP39 seed
 *   - BIP32 spec test vector 1 for derivation check
 *
 * Reference input:
 *   mnemonic = "abandon abandon abandon abandon abandon abandon
 *               abandon abandon abandon abandon abandon about"
 *   passphrase = "" (empty)
 *
 * Canonical outputs (computed and re-confirmed in Python 3.12 + ecdsa 0.19.2):
 *
 *   BIP39 seed (64 bytes, no passphrase):
 *     5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1
 *     9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4
 *
 *   First 3 addresses at m/44'/2222'/0'/0/i, i=0..2:
 *     i=0: TDrHzzu8pwHh1i4p2UwCFcQi3ktsBXpDDy  (Python canonical)
 *
 * The expected SEED hex is hardcoded here as a regression check: if a future
 * change breaks PBKDF2, this test catches it immediately. The first-address
 * value is cross-checked against Python derivation of the same mnemonic.
 */

#include <stdio.h>
#include <string.h>

#include "bip39.h"
#include "bip32.h"
#include "bip44.h"

#include "test_helpers.h"

static const char *EXPECTED_SEED_HEX =
    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
    "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

static const char *EXPECTED_ADDR_0 = "TDrHzzu8pwHh1i4p2UwCFcQi3ktsBXpDDy";

int main(void) {
    const char *mnem =
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about";
    const char *passphrase = "";

    uint8_t seed[64];
    int mn_rc = bip39_mnemonic_to_seed(mnem, passphrase, seed);
    if (mn_rc != 0) {
        fprintf(stderr, "mnemonic_to_seed failed: rc=%d\n", mn_rc); return 1;
    }

    char hex[129];
    bin2hex(seed, 64, hex);
    printf("seed (hex): %s\n", hex);

    int seed_ok = (strcmp(hex, EXPECTED_SEED_HEX) == 0);
    printf("seed matches canonical BIP39 V1: %s\n", seed_ok ? "YES" : "NO");
    if (!seed_ok) {
        printf("\n  want: %s\n", EXPECTED_SEED_HEX);
        return 1;
    }

    /* Derive m/44'/2222'/0'/0/0 .. /0/2 and print. */
    tri_extkey_t master;
    if (!tri_bip32_master_from_seed(seed, 64, &master)) {
        fprintf(stderr, "master_from_seed failed\n"); return 1;
    }
    printf("\nfirst 3 receiving addresses (m/44'/2222'/0'/0/i):\n");
    int addr0_ok = 0;
    for (uint32_t i = 0; i < 3; i++) {
        uint8_t addr[64] = {0};
        if (!tri_derive_triangles_addr(&master, 0, 0, i, addr, sizeof(addr))) {
            fprintf(stderr, "addr derive failed at i=%u\n", i); return 1;
        }
        printf("  /0/%u -> %s\n", i, (char *)addr);
        if (i == 0 && strcmp((char *)addr, EXPECTED_ADDR_0) == 0) addr0_ok = 1;
    }
    printf("\naddr 0 canonical check: %s\n", addr0_ok ? "PASS" : "FAIL");
    printf("  want: %s\n", EXPECTED_ADDR_0);
    return (seed_ok && addr0_ok) ? 0 : 1;
}
