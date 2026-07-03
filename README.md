# triangles-paper-wallet

**Offline air-gapped paper-wallet generator for Triangles (TRI).**

A small C CLI that mints a BIP39 mnemonic + first BIP44 receiving address
without ever touching the network. Run it on a machine that has never
been, and never will be, connected to the internet.

```
triangles-mint-paper-wallet
    --words 12            # 12 or 24
    --passphrase ""       # BIP39 25th word (empty = none)
    --coin-type 2222      # Triangles is BIP44 coin type 2222
    --output ./wallet.pdf
```

```
┌──────────────────────────────────────────────────────────────────┐
│  This tool generates a private key.                              │
│                                                                  │
│  RUN ONLY ON A MACHINE THAT WILL NEVER CONNECT TO                │
│  THE INTERNET AGAIN.                                             │
│                                                                  │
│  After running, physically destroy any bootable network device   │
│  before printing. See docs/AIRGAP.md.                            │
└──────────────────────────────────────────────────────────────────┘
```

---

## What this is

A thin shell around **upstream Bitcoin's libsecp256k1 v0.7.1** — the same
audited cryptographic library that powers Bitcoin Core, plus a tiny
self-contained BIP39/BIP32/BIP44/Base58 layer over the top, all wired
together by ~600 LoC of CLI glue.

```
entropy ──► BIP39 mnemonic ──► PBKDF2 ──► BIP32 seed ──► secp256k1 ─┐
                                                                      │
BIP44 path ──► m/44'/2222'/0'/0/0 ──► compressed pubkey ──► RIPEMD160 │
                                                                    ▼
                                                   ┌── Base58Check encode (vbyte 0x41)
                                                   ▼
                                                TRI address (starts with T)
```

### Cryptographic primitives

| primitive           | source                      | audited by            |
|---------------------|-----------------------------|-----------------------|
| secp256k1 EC math   | `bitcoin-core/secp256k1@v0.7.1` (submodule) | Bitcoin Core security team |
| SHA-256, SHA-512    | self-contained, FIPS 180-4  | self-tested vs RFC    |
| HMAC-SHA512         | RFC 2104, sha512 above      | self-tested vs RFC 4231 |
| PBKDF2-HMAC-SHA512  | RFC 8018                    | self-tested vs RFC 7914 |
| RIPEMD-160          | self-contained, RFC 2286    | self-tested vs RFC test vectors |
| Base58Check         | Bitcoin reference alphabet  | round-trip tested     |

### What this is NOT

- ❌ **Not a hosted service.** We do not run a website that generates keys.
- ❌ **Not a web wallet.** No JavaScript, no browser.
- ❌ **Not connected to the Triangles daemon.** It does not call into
  `triangle_prunedassetd` or any RPC.
- ❌ **Not a BIP32-account generator.** This gives you account `0`,
  external chain, index `0`. Multiple accounts / chains / indices are
  trivially derivable but are out of scope for v0.1.

---

## Threat model — short version

| defends against                              | does NOT defend against                |
|----------------------------------------------|----------------------------------------|
| Network-based key theft                      | Compromised CPU / firmware              |
| Supply-chain keylogging in a JS wallet       | Compromised printer firmware            |
| OS-level clipboard snooping                  | Shoulders over your shoulder              |
| Browser-borne key-stealing malware           | The user's own lack of OpSec            |
| Man-in-the-middle attacks on online tools    | The seed phrase sitting in a photo on your phone |

Full threat model: [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)
Air-gap workflow: [docs/AIRGAP.md](docs/AIRGAP.md)
Verification guide: [docs/VERIFICATION.md](docs/VERIFICATION.md)

---

## Build

```sh
git clone --recurse-submodules https://github.com/SamiAhmed7777/triangles-paper-wallet.git
cd triangles-paper-wallet
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

The binary is fully reproducible under `SOURCE_DATE_EPOCH`: two independent
cmake invocations produce byte-identical `triangles-mint-paper-wallet`.

---

## Test

```sh
ctest --test-dir build --output-on-failure
```

Five suites run:

| test             | purpose                                              |
|------------------|------------------------------------------------------|
| `paper_selftest` | 11 canonical crypto vectors (SHA-256, RIPEMD-160, HMAC-SHA-512, PBKDF2, Base58Check) |
| `paper_bip32`    | BIP-32 spec vectors 1 + 2                            |
| `paper_bip44_canonical` | First-address cross-check against Python `ecdsa` |
| `paper_roundtrip`| BIP-39 `abandon`×11 + `about` seed → `TDrHzzu8…DDy`  |
| `paper_e2e`      | 12-case production invariant suite (CSPRNG, checksum, all address well-formed, etc.) |

---

## Verify (airgap sanity)

After building, **verify the binary has no network symbols**:

```sh
nm -D --undefined-only build/src/triangles-mint-paper-wallet \
  | grep -Ei 'socket|connect|gethostbyname|getaddrinfo|http_|tls_|ssl_'
# (no output = pass)
```

The CI workflow [`.github/workflows/offline-build.yml`](.github/workflows/offline-build.yml)
runs this check + reproducibility + every test on every push to `main` and
every PR. **A PR cannot merge if the airgap gate fires.**

---

## Contributing

PRs that touch the cryptographic core are merged only after a code review by two maintainers.
