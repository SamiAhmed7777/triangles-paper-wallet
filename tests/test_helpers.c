#include "test_helpers.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

int hex2bin(const char *hex, unsigned char *out, size_t outlen) {
    size_t n = strlen(hex);
    if (n != outlen * 2) return 1;
    for (size_t i = 0; i < outlen; i++) {
        int hi = hex[i*2], lo = hex[i*2+1];
        if (!isxdigit(hi) || !isxdigit(lo)) return 1;
        hi = (hi <= '9') ? (hi - '0') : (tolower(hi) - 'a' + 10);
        lo = (lo <= '9') ? (lo - '0') : (tolower(lo) - 'a' + 10);
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 0;
}

/* Allow variable-length seeds: takes a hex string and produces the byte array.
 * Returns the number of bytes written. Returns 0 on error. */
size_t hex2bin_var(const char *hex, unsigned char *out, size_t out_max) {
    size_t n = strlen(hex);
    if (n % 2 != 0 || (n / 2) > out_max) return 0;
    size_t bytes = n / 2;
    for (size_t i = 0; i < bytes; i++) {
        int hi = hex[i*2], lo = hex[i*2+1];
        if (!isxdigit(hi) || !isxdigit(lo)) return 0;
        hi = (hi <= '9') ? (hi - '0') : (tolower(hi) - 'a' + 10);
        lo = (lo <= '9') ? (lo - '0') : (tolower(lo) - 'a' + 10);
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return bytes;
}

void bin2hex(const unsigned char *in, size_t len, char *out) {
    static const char *H = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i*2]   = H[in[i] >> 4];
        out[i*2+1] = H[in[i] & 0xf];
    }
    out[len*2] = '\0';
}
