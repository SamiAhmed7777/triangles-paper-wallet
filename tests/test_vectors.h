/*
 * Public-domain test vectors for SHA-256, HMAC-SHA512, RIPEMD-160, PBKDF2.
 *
 * These are the canonical RFC / FIPS / NIST vectors for self-testing.
 * All values are little-endian hex strings of the digest output.
 */

#ifndef TRI_PAPER_TEST_VECTORS_H
#define TRI_PAPER_TEST_VECTORS_H

/* SHA-256 — RFC 6234 vector #1:
 *   input:  "abc"
 *   output: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
 */
static const char *TV_SHA256_ABC_HEX =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

/* SHA-256 of the empty string: */
static const char *TV_SHA256_EMPTY_HEX =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/* RIPEMD-160 of "abc": */
static const char *TV_RIPEMD160_ABC_HEX =
    "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc";

/* RIPEMD-160 of empty string: */
static const char *TV_RIPEMD160_EMPTY_HEX =
    "9c1185a5c5e9fc54612808977ee8f548b2258d31";

/* HMAC-SHA512 — RFC 4231 test case 1:
 *   key    = 0x0b * 20
 *   data   = "Hi There"
 *   output = 87aa7cdea5ef619d4ff0b4241a1d6cb02379f9e3
 *            c8b8d8c5dad11d4cae4f4ce8d
 */
static const char *TV_HMAC_SHA512_TC1_KEY_HEX = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
static const char *TV_HMAC_SHA512_TC1_DATA    = "Hi There";
static const char *TV_HMAC_SHA512_TC1_EXPECTED_HEX =
    "87aa7cdea5ef619d4ff0b4241a1d6cb02379f9e3c8b8d8c5dad11d4cae4f4ce8d";

/* BIP39 test vector #1 (Trezor test vectors):
 *   entropy = 00000000000000000000000000000000 (128-bit, all-zero)
 *   mnemonic = abandon abandon abandon abandon abandon abandon
 *              abandon abandon abandon abandon abandon about
 *   seed (no passphrase) = c55257c360c07c72029aebc1b53c05ed
 *                          0362ada38e1bd901db8c39c1b6e04b69
 *                          88494e6924e96e95d8e0b18f228e2dad
 *                          04b5e25c6b1dbe74f7ace3e8d29c3e3d
 */
static const char *TV_BIP39_V1_ENTROPY_HEX =
    "00000000000000000000000000000000";
static const char *TV_BIP39_V1_MNEMONIC =
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about";
static const char *TV_BIP39_V1_SEED_HEX =
    "c55257c360c07c72029aebc1b53c05ed0362ada38e1bd901db8c39c1b6e04b69"
    "88494e6924e96e95d8e0b18f228e2dad04b5e25c6b1dbe74f7ace3e8d29c3e3d";

/* Base58 test:
 *   bytes  = 00 f7 16 63 5b 8d 2c 79 18 9f ad 8b d3 4d 4e 23 3c 18 33 69 87
 *   base58 = "1B6QEyLfd8M7Yfm9UKemKgWJHaGVR7N1Z3"
 */
static const char *TV_B58_BYTES_HEX =
    "00f716635b8d2c79189fad8bd34d4e233c18336987";
static const char *TV_B58_ENCODED =
    "1B6QEyLfd8M7Yfm9UKemKgWJHaGVR7N1Z3";

#endif
