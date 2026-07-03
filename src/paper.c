/* src/paper.c — offline paper wallet output formatting.
 *
 * Produces printable plain-text (terminal-friendly), HTML (browser-printable),
 * and a minimal raw mnemonic+addresses dump.
 *
 * SECURITY: this module must NEVER touch the network, /tmp, or any file other
 * than the explicit output paths passed by main.c. It does not link any
 * socket/ssl/curl/http code (verified by CI nm-grep).
 */
#include "paper.h"
#include "bip39.h"
#include "bip32.h"
#include "bip44.h"
#include "base58.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>

/* format_words: break a 24-word mnemonic into groups of 4 for printing. */
static void format_words(const char *mnemonic, int n_cols, char *out, size_t out_len)
{
    if (n_cols < 1) n_cols = 4;
    char buf[512];
    strncpy(buf, mnemonic, sizeof buf - 1);
    buf[sizeof buf - 1] = '\0';

    /* Split on space. */
    char *tokens[32];
    int n = 0;
    char *save = NULL;
    char *p = strtok_r(buf, " ", &save);
    while (p && n < 32) { tokens[n++] = p; p = strtok_r(NULL, " ", &save); }

    /* Format in rows of n_cols. */
    int pos = 0;
    for (int i = 0; i < n; i++) {
        int printed = snprintf(out + pos, out_len - (size_t)pos,
                               "%s%-2d. %-12s",
                               (i % n_cols == 0 && i > 0) ? "\n" : "",
                               i + 1, tokens[i]);
        if (printed < 0) return;
        pos += printed;
    }
    out[pos++] = '\n';
    out[pos] = '\0';
}

static const char *today_iso(void)
{
    static char iso[16];
    time_t t = time(NULL);
    struct tm tm;
    if (localtime_r(&t, &tm) == NULL) { strncpy(iso, "1970-01-01", sizeof iso); return iso; }
    if (strftime(iso, sizeof iso, "%Y-%m-%d", &tm) == 0) { strncpy(iso, "1970-01-01", sizeof iso); }
    return iso;
}

int paper_print_text(FILE *out,
                     const char *mnemonic,
                     const char *passphrase,
                     const tri_extkey_t *master,
                     uint32_t n_addrs)
{
    if (!out || !mnemonic || !master) return 0;

    fprintf(out,
        "============================================================\n"
        "  TRIANGLES PAPER WALLET  —  OFFLINE GENERATOR\n"
        "============================================================\n"
        "  Generated: %s\n"
        "  Words:     24 (BIP39 English)\n"
        "  Network:   Triangles mainnet (TRI coin type 2222)\n"
        "  Prefix:    m/44'/2222'/0'/0/i\n"
        "============================================================\n\n",
        today_iso());

    fprintf(out, "MNEMONIC (24 words — keep this paper offline and secret):\n\n");
    char grid[1024];
    format_words(mnemonic, 4, grid, sizeof grid);
    fputs(grid, out);

    if (passphrase && passphrase[0]) {
        fprintf(out, "\nBIP39 PASSPHRASE (25th word — store SEPARATELY, never with the mnemonic):\n"
                     "  %s\n\n", passphrase);
    } else {
        fprintf(out, "\nBIP39 PASSPHRASE: <none>\n\n");
    }

    fprintf(out,
        "FIRST %u RECEIVING ADDRESSES (m/44'/2222'/0'/0/i):\n\n"
        "  Note: a Triangles daemon importing this mnemonic will derive the same\n"
        "        addresses via triangles-cli hdrestore \"<words>\" [passphrase].\n\n",
        n_addrs);

    for (uint32_t i = 0; i < n_addrs; i++) {
        char addr[64];
        if (!tri_derive_triangles_addr(master, 0, 0, i, (uint8_t *)addr, sizeof addr)) {
            fprintf(out, "  [%u]  (derivation failed)\n", i);
            continue;
        }
        /* pubkey hex (so user can sanity-verify against any conforming wallet) */
        uint8_t fp[4];
        tri_bip32_fingerprint(master, fp);
        fprintf(out, "  [%u]  T%c...   %s\n", i, fp[0], addr);
    }

    fprintf(out,
        "\n============================================================\n"
        "  SAFETY CHECKS (do these before trusting the addresses):\n"
        "  [ ] Print this on a non-networked device.\n"
        "  [ ] Verify the fingerprint matches any device restoration.\n"
        "  [ ] Triangles daemon:    triangles-cli hdrestore \"<24 words>\" [passphrase]\n"
        "  [ ] Confirm getnewaddress == the address above for [0].\n"
        "============================================================\n");
    return 1;
}

int paper_print_html(FILE *out,
                     const char *mnemonic,
                     const char *passphrase,
                     const tri_extkey_t *master,
                     uint32_t n_addrs)
{
    if (!out || !mnemonic || !master) return 0;

    char grid[1024];
    format_words(mnemonic, 4, grid, sizeof grid);

    fprintf(out,
        "<!DOCTYPE html>\n"
        "<html lang=\"en\"><head><meta charset=\"utf-8\">\n"
        "<title>Triangles Paper Wallet</title>\n"
        "<style>\n"
        "body{font-family:monospace;max-width:760px;margin:2em auto;padding:1em;border:2px dashed #c33;}\n"
        "h1{margin:0 0 .2em 0;}h2{margin-top:1.5em;border-bottom:1px solid #ccc;}\n"
        ".grid{font-size:1.4em;line-height:1.6;background:#faf6f0;padding:1em;border:1px solid #ddd;}\n"
        ".warn{background:#fff3cd;border:1px solid #856404;padding:.7em;margin-top:1em;}\n"
        ".addr{font-weight:bold;}\n"
        "table{border-collapse:collapse;width:100%%;margin-top:1em;}\n"
        "td,th{border:1px solid #ccc;padding:.4em;text-align:left;}\n"
        "</style></head><body>\n"
        "<h1>Triangles Paper Wallet</h1>\n"
        "<p><strong>Date:</strong> %s &nbsp; | &nbsp; <strong>Coin type:</strong> 2222 (Triangles) &nbsp; | &nbsp; <strong>Path:</strong> m/44&#39;/2222&#39;/0&#39;/0/i</p>\n"
        "<div class=\"warn\"><strong>SECRET.</strong> Anyone with these 24 words and the passphrase can spend the funds. Print only on an offline device and store in a fireproof location.</div>\n"
        "<h2>Mnemonic (24 words)</h2>\n"
        "<div class=\"grid\">\n<pre>%s</pre></div>\n",
        today_iso(), grid);

    if (passphrase && passphrase[0]) {
        fprintf(out,
            "<h2>BIP39 passphrase (25th word)</h2>\n"
            "<p>Store this <strong>separately</strong> from the mnemonic. A thief with\n"
            "the words but not the passphrase cannot move funds.</p>\n"
            "<div class=\"grid\"><pre>%s</pre></div>\n", passphrase);
    } else {
        fprintf(out, "<h2>BIP39 passphrase</h2><p><em>None.</em></p>\n");
    }

    fprintf(out, "<h2>First %u receiving addresses</h2><table><tr><th>#</th><th>Address</th></tr>\n", n_addrs);
    for (uint32_t i = 0; i < n_addrs; i++) {
        char addr[64];
        if (tri_derive_triangles_addr(master, 0, 0, i, (uint8_t *)addr, sizeof addr)) {
            fprintf(out, "<tr><td>%u</td><td class=\"addr\">%s</td></tr>\n", i, addr);
        }
    }
    fprintf(out,
        "</table>\n"
        "<h2>How to restore on the Triangles daemon</h2>\n"
        "<pre>triangles-cli hdrestore \"%s\"%s%s</pre>\n"
        "<p>After restoring, the address at index 0 from <code>triangles-cli getnewaddress</code> must equal the address above for [0].</p>\n"
        "</body></html>\n",
        mnemonic,
        (passphrase && passphrase[0]) ? " " : "",
        (passphrase && passphrase[0]) ? passphrase : "");
    return 1;
}
