#ifndef TRI_PAPER_H
#define TRI_PAPER_H

#include <stdio.h>
#include "bip32.h"

/* Print a Triangles paper wallet to FILE* `out` as plain text. */
int paper_print_text(FILE *out,
                     const char *mnemonic,
                     const char *passphrase,
                     const tri_extkey_t *master,
                     uint32_t n_addrs);

/* Print HTML form (browser-printable, cut-and-fold). */
int paper_print_html(FILE *out,
                     const char *mnemonic,
                     const char *passphrase,
                     const tri_extkey_t *master,
                     uint32_t n_addrs);

#endif
