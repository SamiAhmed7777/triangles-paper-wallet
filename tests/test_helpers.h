#ifndef TEST_HELPERS_H
#define TEST_HELPERS_H
#include <stddef.h>
int  hex2bin(const char *hex, unsigned char *out, size_t outlen);
void bin2hex(const unsigned char *in, size_t len, char *out);
#endif
