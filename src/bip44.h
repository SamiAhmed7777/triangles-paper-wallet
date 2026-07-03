/* BIP44 derivation helper — produces Triangles addresses for the standard
 * path:
 *    m/44'/2222'/account'/change/index
 *
 * Triangles defaults to account=0, change=0 (external / receiving).
 * The 25th word (BIP39 passphrase) is owned at this layer only as far as
 * needed to derive the same addresses the daemon would produce.
 */
#ifndef TRI_BIP44_H
#define TRI_BIP44_H

#include <stdint.h>
#include "base58.h"
#include "bip32.h"

#define TRI_COIN_TYPE_HARDENED ((2222u | 0x80000000u))

/* Full default external path: m/44'/2222'/0'/0/i */
#define TRI_DEFAULT_PATH_PREFIX 4    /* depth of m/44'/2222'/0'/0 — same as index count */

/* Derive Triangles address at path m/44'/2222'/0'/0/index.
 *   master: extended master key from BIP39 seed
 *   account: usually 0
 *   change: 0 for receiving (external), 1 for change (internal)
 *   index: address index (typically 0..N)
 *   addr_out: caller-allocated buffer of at least 64 bytes (Base58Check encoded)
 * Returns 1 on success, 0 on failure.
 */
int tri_derive_triangles_addr(const tri_extkey_t *master,
                              uint32_t account, uint32_t change, uint32_t index,
                              uint8_t *addr_out, size_t addr_out_len);

#endif
