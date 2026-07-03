/*
 * Base58Check encoding / decoding. Bitcoin alphabet.
 *
 * Triangles uses the standard Bitcoin Base58Check alphabet:
 *   "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
 *
 * Reference: Bitcoin's base58.cpp. Public domain.
 */
#include "base58.h"
#include "sha256.h"
#include <string.h>

static const char ALPHABET[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static const int8_t DECODE_MAP[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8,-1,-1,-1,-1,-1,-1,
    -1, 9,10,11,12,13,14,15,16,-1,17,18,19,20,21,-1,
    22,23,24,25,26,27,28,29,30,31,32,-1,-1,-1,-1,-1,
    -1,33,34,35,36,37,38,39,40,41,42,43,-1,44,45,46,
    47,48,49,50,51,52,53,54,55,56,57,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};

static int b58_encode_raw(const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t *out_len)
{
    /* Skip leading zeros. Each leading-zero byte is represented by a
       leading '1' character (ALPHABET[0]) in the result. */
    size_t zeros = 0;
    while (zeros < in_len && in[zeros] == 0) zeros++;

    uint8_t buf[256] = {0};
    size_t buflen = 1;
    char rev[256];
    int rev_i = 0;
    for (size_t i = zeros; i < in_len; i++) {
        int carry = in[i];
        for (size_t j = 0; j < buflen; j++) {
            carry += 256 * buf[j];
            buf[j] = carry % 58;
            carry /= 58;
        }
        while (carry) {
            if (buflen >= sizeof buf) return -1;
            buf[buflen++] = carry % 58;
            carry /= 58;
        }
    }
    /* buf[] holds the base-58 digits, least-significant first.
       Reverse them AND prepend the leading-'1' chars (one per leading zero). */
    for (size_t j = 0; j < zeros; j++) rev[rev_i++] = ALPHABET[0];
    for (size_t j = buflen; j > 0; j--) rev[rev_i++] = ALPHABET[buf[j-1]];

    if ((size_t)rev_i > *out_len) return -1;
    memcpy(out, rev, rev_i);
    *out_len = rev_i;
    return 0;
}

static int b58_decode_raw(const char *in, size_t in_len,
                          uint8_t *out, size_t *out_len)
{
    if (in_len == 0) return -1;
    size_t zeros = 0;
    while (zeros < in_len && in[zeros] == ALPHABET[0]) zeros++;

    uint8_t buf[256] = {0};
    size_t buflen = 0;

    for (size_t i = zeros; i < in_len; i++) {
        int8_t c = DECODE_MAP[(uint8_t)in[i]];
        if (c < 0) return -1;
        int carry = c;
        for (size_t j = 0; j < buflen; j++) {
            carry += 58 * buf[j];
            buf[j] = carry & 0xff;
            carry >>= 8;
        }
        while (carry) {
            if (buflen >= sizeof buf) return -1;
            buf[buflen++] = carry & 0xff;
            carry >>= 8;
        }
    }

    size_t result_len = buflen + zeros;
    if (result_len > *out_len) return -1;
    for (size_t i = 0; i < buflen; i++) out[result_len - 1 - i] = buf[i];
    for (size_t i = 0; i < zeros; i++) out[i] = 0;
    *out_len = result_len;
    return 0;
}

int b58check_encode(const uint8_t *in, size_t in_len,
                    uint8_t *out, size_t *out_len)
{
    /* Append 4-byte double-SHA256 checksum */
    uint8_t buf[256];
    if (in_len + 4 > sizeof buf) return -1;
    memcpy(buf, in, in_len);
    uint8_t h1[SHA256_DIGEST_LEN], h2[SHA256_DIGEST_LEN];
    sha256(in, in_len, h1);
    sha256(h1, SHA256_DIGEST_LEN, h2);
    memcpy(buf + in_len, h2, 4);

    size_t olen = *out_len;
    int rv = b58_encode_raw(buf, in_len + 4, out, &olen);
    if (rv == 0) *out_len = olen;
    return rv;
}

int b58check_decode(const char *in,
                    uint8_t *out, size_t *out_len)
{
    size_t in_len = strlen(in);
    uint8_t buf[256];
    size_t blen = sizeof buf;
    int rv = b58_decode_raw(in, in_len, buf, &blen);
    if (rv != 0) return rv;

    if (blen < 4) return -1;
    uint8_t h1[SHA256_DIGEST_LEN], h2[SHA256_DIGEST_LEN];
    sha256(buf, blen - 4, h1);
    sha256(h1, SHA256_DIGEST_LEN, h2);
    if (memcmp(h2, buf + blen - 4, 4) != 0) return -2;

    if (blen - 4 > *out_len) return -3;
    memcpy(out, buf, blen - 4);
    *out_len = blen - 4;
    return 0;
}
