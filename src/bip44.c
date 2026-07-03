/*
 * BIP44 derivation producing a Triangles address (Base58Check with version byte
 * 0x41 over the HASH160 of the compressed secp256k1 public key).
 *
 * Mirrors the daemon's hd::DeriveTriangles:
 *     path = m / 44' / 2222' / account' / change / index
 *
 * Any deviation in path, version byte, or Base58Check encoding produces a
 * DIFFERENT address string. The cross-check with the daemon is done in
 * tests/roundtrip_daemon.c.
 */

#include "bip44.h"

#include <stdint.h>
#include <string.h>

#include "bip32.h"
#include "ripemd160.h"
#include "sha256.h"

#include <secp256k1.h>

#define TRI_VERSION_BYTE 0x41   /* mainnet P2PKH -> address starts with T */
#define TRI_BASE58CHECK_MAXLEN 36  /* 1 ver + 20 hash + 4 checksum + 1 '\0' */

/* SHA256 then RIPEMD160 (a.k.a. HASH160) — used for the address. */
static void hash160(const uint8_t *data, size_t len, uint8_t out[20])
{
    uint8_t sha[32];
    sha256(data, len, sha);
    tri_ripemd160(sha, 32, out);
}

/* Triangles address: 1 version byte || 20-byte hash160, then Base58Check
 * (which appends 4-byte checksum and encodes). */
static int encode_triangles_address(const uint8_t hash160_out[20], uint8_t *addr_out,
                                    size_t addr_out_len)
{
    uint8_t buf[1 + 20];
    buf[0] = TRI_VERSION_BYTE;
    memcpy(buf + 1, hash160_out, 20);

    size_t out_len = addr_out_len;
    if (b58check_encode(buf, sizeof(buf), addr_out, &out_len) != 0) return 0;
    /* null-terminate */
    if (out_len < addr_out_len) addr_out[out_len] = '\0';
    return 1;
}

int tri_derive_triangles_addr(const tri_extkey_t *master,
                              uint32_t account, uint32_t change, uint32_t index,
                              uint8_t *addr_out, size_t addr_out_len)
{
    uint32_t path[] = {
        44u | 0x80000000u,                     /* 44'  */
        2222u | 0x80000000u,                   /* 2222' */
        account | 0x80000000u,                 /* account' */
        change,                                /* change  */
        index,                                 /* index   */
    };
    tri_extkey_t leaf;
    if (!tri_bip32_derive_path(master, path, 5, &leaf)) return 0;

    /* Compute HASH160(compressed_pubkey). */
    uint8_t h[20];
    hash160(leaf.pubkey_compressed, 33, h);

    return encode_triangles_address(h, addr_out, addr_out_len);
}
