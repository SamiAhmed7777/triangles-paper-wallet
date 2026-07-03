/*
 * BIP39 — mnemonic generation + seed derivation.
 *
 * Generation flow:
 *   1. Acquire 128 or 256 bits of entropy from the OS CSPRNG
 *   2. Append a SHA-256-based checksum
 *   3. Split the resulting bit string into 11-bit groups
 *   4. Map each group to a word in the BIP39 wordlist
 */
#define _POSIX_C_SOURCE 200809L  /* for strtok_r */

#include "bip39.h"
#include "third_party_bip39_english.h"
#include "entropy.h"
#include "sha256.h"
#include "pbkdf2.h"

#include <stdio.h>
#include <string.h>

/* Find index of word in the BIP39 wordlist. Returns -1 if not found. */
static int word_index(const char *word)
{
    /* Binary search (words are alphabetical in BIP39) */
    int lo = 0, hi = 2047;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        int cmp = strcmp(word, BIP39_WORDLIST_EN[mid]);
        if (cmp == 0) return mid;
        if (cmp < 0) hi = mid - 1;
        else lo = mid + 1;
    }
    return -1;
}

/* Public — linear scan is fine for validation. Exposed via bip39.h. */
int bip39_is_known_word(const char *word)
{
    if (!word || !word[0]) return 0;
    return word_index(word) >= 0;
}

/* Public — return the n-th BIP39 word (0..2047). Exposed via bip39.h.
 * Returns NULL on out-of-range. */
const char *bip39_word(int n)
{
    if (n < 0 || n >= BIP39_WORDS) return NULL;
    return BIP39_WORDLIST_EN[n];
}

/* Public — validate a 12- or 24-word mnemonic by checking the BIP39
 * checksum bit. The last word encodes chk_bits of SHA-256(entropy);
 * we recover the entropy bits (dropping the trailing chk_bits), hash
 * them, and compare. */
int bip39_validate_mnemonic(const char *mnemonic)
{
    if (!mnemonic || !mnemonic[0]) return 0;

    /* Copy on stack because strtok modifies. */
    char buf[256];
    strncpy(buf, mnemonic, sizeof buf - 1);
    buf[sizeof buf - 1] = '\0';

    char *tokens[24];
    int n = 0;
    char *save = NULL;
    for (char *p = strtok_r(buf, " ", &save); p && n < 24; p = strtok_r(NULL, " ", &save))
        tokens[n++] = p;
    if (n != 12 && n != 24) return 0;

    /* Convert each word → 11-bit index. */
    uint32_t idx[24];
    for (int i = 0; i < n; i++) {
        int k = word_index(tokens[i]);
        if (k < 0) return 0;
        idx[i] = (uint32_t)k;
    }

    int ent_bits  = (n == 12) ? 128 : 256;
    int chk_bits  = ent_bits / 32;
    int total_bits = ent_bits + chk_bits;
    int ent_bytes  = ent_bits / 8;

    /* Reconstruct bytes from bit stream. */
    uint8_t bits[33] = {0};
    for (int i = 0; i < n; i++) {
        uint32_t v = idx[i];
        /* Write 11 bits starting at bit position i*11. */
        int bit_off = i * 11;
        for (int b = 0; b < 11; b++) {
            int bit = (v >> (10 - b)) & 1;
            int abs = bit_off + b;
            bits[abs / 8] |= (uint8_t)(bit << (7 - (abs % 8)));
        }
    }
    /* Verify the trailing chk_bits match SHA-256(bits[0..ent_bytes]). */
    uint8_t hash[32];
    sha256(bits, ent_bytes, hash);

    int ok = 1;
    for (int i = 0; i < chk_bits; i++) {
        int bit_expected = (hash[i / 8] >> (7 - (i % 8))) & 1;
        int bit_actual   = (bits[ent_bytes + i / 8] >> (7 - (i % 8))) & 1;
        if (bit_expected != bit_actual) { ok = 0; break; }
    }
    /* For an n-bit stream, only the first `total_bits` bits matter; ignore
     * trailing zero bits in bits[ent_bytes]. */
    (void)total_bits;
    return ok ? 1 : 0;
}

int bip39_generate(int n_words, char *out, size_t out_len)
{
    if (n_words != 12 && n_words != 24) return -1;

    int ent_bytes = (n_words == 12) ? 16 : 32;        /* 128 / 256 bits */
    int ent_bits  = ent_bytes * 8;
    int chk_bits  = ent_bits / 32;                     /* 4 / 8 bits */
    int total_bits = ent_bits + chk_bits;              /* 132 / 264 */

    uint8_t entropy[32];
    if (get_crypto_entropy(entropy, ent_bytes) != 0) return -1;

    /* Compute checksum = first chk_bits of SHA-256(entropy) */
    uint8_t hash[32];
    sha256(entropy, ent_bytes, hash);

    /* Build a bit string: entropy || chk_bits of hash, big-endian
     * total_bits bits packed left-to-right. */
    uint8_t bits[33] = {0};
    memcpy(bits, entropy, ent_bytes);
    for (int i = 0; i < chk_bits; i++) {
        int bit = (hash[i / 8] >> (7 - (i % 8))) & 1;
        bits[ent_bytes + i / 8] |= (uint8_t)(bit << (7 - (i % 8)));
    }

    /* Convert to words. Each word indexes 11 bits of the bit stream. */
    int n_groups = total_bits / 11;
    int pos = 0;
    for (int i = 0; i < n_groups; i++) {
        int bit_off = i * 11;
        /* Pull a 16-bit window starting at bit_off and read bits 11..21 of it. */
        int byte_off = bit_off / 8;
        int shift = bit_off % 8;
        uint32_t window =
            ((uint32_t)bits[byte_off]     << 16) |
            ((uint32_t)bits[byte_off + 1] <<  8) |
            ((uint32_t)bits[byte_off + 2]      );
        uint32_t v = (window >> (24 - 11 - shift)) & 0x07ff;

        const char *w = BIP39_WORDLIST_EN[v];
        int written = snprintf(out + pos, out_len - (size_t)pos,
                               "%s%s", i == 0 ? "" : " ", w);
        if (written < 0 || (size_t)written >= out_len - (size_t)pos) return -1;
        pos += written;
    }
    return 0;
}

int bip39_mnemonic_to_seed(const char *mnemonic,
                           const char *passphrase,
                           uint8_t seed[64])
{
    /* BIP39 seed = PBKDF2-HMAC-SHA512(mnemonic_as_utf8, "mnemonic" || passphrase_as_utf8, 2048) */
    const char *salt_prefix = "mnemonic";
    size_t pp_len = passphrase ? strlen(passphrase) : 0;
    char salt[256];
    int n = snprintf(salt, sizeof salt, "%s%s", salt_prefix, passphrase ? passphrase : "");
    if (n < 0 || (size_t)n >= sizeof salt) return -1;
    (void)pp_len;

    pbkdf2_hmac_sha512((const uint8_t *)mnemonic, strlen(mnemonic),
                       (const uint8_t *)salt, (size_t)n,
                       2048,
                       seed, 64);
    return 0;
}
