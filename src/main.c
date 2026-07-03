/* src/main.c — triangles-paper-wallet CLI.
 *
 *   triangles-paper-wallet --bits 256 [--passphrase "..."] [--addrs 5]
 *                          [--text out.txt | --html out.html]
 *
 * Pure offline generator. Reads entropy from OS CSPRNG (--no-docstrings: see entropy.c).
 *
 * Exit codes:
 *   0 — success
 *   1 — usage error
 *   2 — generation error (entropy failure, address derivation failure)
 */
#define _POSIX_C_SOURCE 200809L  /* for getopt_long on glibc */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include "bip39.h"
#include "bip32.h"
#include "paper.h"

static void usage(FILE *f)
{
    fprintf(f,
        "Usage: triangles-paper-wallet [options]\n"
        "  --bits N         128 or 256 (default 256 → 24 words)\n"
        "  --passphrase P   BIP39 passphrase (stored SEPARATELY; optional)\n"
        "  --addrs N        How many first-addresses to print (default 5)\n"
        "  --text FILE      Write text report to FILE (default stdout)\n"
        "  --html FILE      Write HTML report to FILE (in addition to text)\n"
        "  --help           This message\n"
        "\n"
        "Examples:\n"
        "  triangles-paper-wallet --bits 256 --text wallet.txt\n"
        "  triangles-paper-wallet --bits 256 --passphrase 'CorrectHorseBatteryStaple!42'\n"
        "                          --html wallet.html --text wallet.txt\n");
}

int main(int argc, char **argv)
{
    int bits = 256;
    const char *passphrase = NULL;
    int n_addrs = 5;
    const char *text_path = NULL;
    const char *html_path = NULL;

    static struct option opts[] = {
        {"bits",       required_argument, 0, 'b'},
        {"passphrase", required_argument, 0, 'p'},
        {"addrs",      required_argument, 0, 'a'},
        {"text",       required_argument, 0, 't'},
        {"html",       required_argument, 0, 'H'},
        {"help",       no_argument,       0, 'h'},
        {0,0,0,0}
    };

    int c;
    while ((c = getopt_long(argc, argv, "b:p:a:t:H:h", opts, NULL)) != -1) {
        switch (c) {
            case 'b': bits = atoi(optarg); break;
            case 'p': passphrase = optarg; break;
            case 'a': n_addrs = atoi(optarg); break;
            case 't': text_path = optarg; break;
            case 'H': html_path = optarg; break;
            case 'h': usage(stdout); return 0;
            default:  usage(stderr); return 1;
        }
    }

    int n_words;
    if (bits == 128)      n_words = 12;
    else if (bits == 256) n_words = 24;
    else {
        fprintf(stderr, "Error: --bits must be 128 or 256 (got %d)\n", bits);
        usage(stderr);
        return 1;
    }

    /* 1. Generate mnemonic */
    char mnemonic[256];
    if (bip39_generate(n_words, mnemonic, sizeof mnemonic) != 0) {
        fprintf(stderr, "Error: BIP39 mnemonic generation failed (entropy read?)\n");
        return 2;
    }

    /* 2. BIP39 → 64-byte seed */
    uint8_t seed[64];
    bip39_mnemonic_to_seed(mnemonic, passphrase ? passphrase : "", seed);

    /* 3. BIP32 master */
    tri_extkey_t master;
    if (!tri_bip32_master_from_seed(seed, 64, &master)) {
        fprintf(stderr, "Error: BIP32 master derivation failed\n");
        return 2;
    }

    /* 4. Output */
    FILE *out = stdout;
    if (text_path) {
        out = fopen(text_path, "w");
        if (!out) { perror(text_path); return 2; }
    }
    if (!paper_print_text(out, mnemonic, passphrase, &master, (uint32_t)n_addrs)) {
        fprintf(stderr, "Error: text print failed\n");
        return 2;
    }
    if (text_path) fclose(out);

    if (html_path) {
        out = fopen(html_path, "w");
        if (!out) { perror(html_path); return 2; }
        if (!paper_print_html(out, mnemonic, passphrase, &master, (uint32_t)n_addrs)) {
            fprintf(stderr, "Error: html print failed\n");
            return 2;
        }
        fclose(out);
    }

    return 0;
}
