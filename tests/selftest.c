/* triangles-paper-wallet comprehensive selftest.
 * All expected values are taken from authoritative sources (openssl,
 * Python hashlib/hmac, RFC 4231, BIP39 spec).
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "ripemd160.h"
#include "sha256.h"
#include "hmac_sha512.h"
#include "pbkdf2.h"
#include "base58.h"

static int hex_eq(const unsigned char *b, size_t n, const char *hex) {
    if (strlen(hex) != n*2) return 0;
    for (size_t i = 0; i < n; i++) {
        char w[3] = {hex[2*i], hex[2*i+1], 0};
        if ((unsigned)strtoul(w, NULL, 16) != b[i]) return 0;
    }
    return 1;
}
static void show_buf(const char *l, const unsigned char *b, size_t n) {
    printf("    %s: ", l);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]); printf("\n");
}
static int total = 0, pass = 0;
#define CHECK(label, got, n, expected) do { total++; \
    if (hex_eq(got, n, expected)) { printf("  PASS %s\n", label); pass++; } \
    else { printf("  FAIL %s\n", label); show_buf("got", got, n); printf("    want %s\n", expected); } \
} while (0)
#define CHECK_STR(label, got, n, expected) do { total++; \
    if ((n) == strlen(expected) && memcmp((got), (expected), (n)) == 0) \
        { printf("  PASS %s\n", label); pass++; } \
    else { printf("  FAIL %s (got=%.*s want=%s)\n", label, (int)(n), (const char*)(got), expected); } \
} while (0)

int main(void) {
    unsigned char out[256];
    size_t outlen;

    /* === SHA-256 === */
    printf("[SHA-256]\n");
    sha256((const uint8_t*)"", 0, out);
    CHECK("sha256(empty)", out, 32,
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    sha256((const uint8_t*)"abc", 3, out);
    CHECK("sha256(abc)", out, 32,
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    {
        const char *s = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        sha256((const uint8_t*)s, strlen(s), out);
        CHECK("sha256(56-byte)", out, 32,
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    }

    /* === RIPEMD-160 === */
    printf("[RIPEMD-160]\n");
    tri_ripemd160((const uint8_t*)"", 0, out);
    CHECK("ripemd160(empty)", out, 20,
          "9c1185a5c5e9fc54612808977ee8f548b2258d31");
    tri_ripemd160((const uint8_t*)"abc", 3, out);
    CHECK("ripemd160(abc)", out, 20,
          "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
    {
        const char *s = "message digest";
        tri_ripemd160((const uint8_t*)s, strlen(s), out);
        CHECK("ripemd160(message digest)", out, 20,
              "5d0689ef49d2fae572b881b123a85ffa21595f36");
    }

    /* === HMAC-SHA512 === */
    printf("[HMAC-SHA512]\n");
    {
        /* RFC 4231 Test Case 1 */
        unsigned char key[20]; memset(key, 0x0b, 20);
        hmac_sha512(key, 20, (const uint8_t*)"Hi There", 8, out);
        CHECK("hmac-sha512 RFC 4231 #1", out, 64,
              "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
    }
    {
        /* RFC 4231 Test Case 3 */
        unsigned char key[20]; memset(key, 0xaa, 20);
        unsigned char data[50]; memset(data, 0xdd, 50);
        hmac_sha512(key, 20, data, 50, out);
        CHECK("hmac-sha512 RFC 4231 #3", out, 64,
              "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb");
    }

    /* === PBKDF2-HMAC-SHA512 (BIP39 spec) === */
    printf("[PBKDF2-HMAC-SHA512]\n");
    {
        const char *m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        const char *p = "TREZOR";
        char salt[64];
        int slen = snprintf(salt, sizeof salt, "mnemonic%s", p);
        pbkdf2_hmac_sha512((const uint8_t*)m, strlen(m), (const uint8_t*)salt, (size_t)slen, 2048, out, 64);
        CHECK("BIP39 seed (abandon×11 about / TREZOR)", out, 64,
              "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04");
    }

    /* === Base58Check === */
    printf("[Base58Check]\n");
    {
        /* version 0x00 + 20 zero-byte hash: canonical "1..." all-1s address */
        unsigned char in[21] = {0};
        outlen = 64;
        b58check_encode(in, 21, out, &outlen);
        CHECK_STR("base58check(0x00 + 0×20)", (char*)out, outlen,
                  "1111111111111111111114oLvT2");
    }
    {
        unsigned char in[21] = {0x00, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
        outlen = 64;
        b58check_encode(in, 21, out, &outlen);
        CHECK_STR("base58check(0x00 + 0x01..0x14)", (char*)out, outlen,
                  "16L5yRNPTuciSgXGHqYwn9N6NeoKqopAu");
    }

    printf("\n=========================================\n");
    printf("RESULT: %d/%d passing\n", pass, total);
    return pass == total ? 0 : 1;
}
