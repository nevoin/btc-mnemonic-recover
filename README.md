# bip39-template-finder

Recover a BIP39 seed phrase by template. Fills `*` wildcards with words from a wordlist and matches the derived key against a target BTC hash160 using BIP44 / BIP49 / BIP84.

Windows, C, OpenSSL + libsecp256k1. Offline. CPU only.

> For recovering your own wallets. Using it against wallets you don't own is illegal.

---

## Speed

Ryzen 9 3950X, 24 threads, `-ch 1000`, `-mode seq`, BIP84, 12-word template:

| Metric                    | Value        |
|---------------------------|--------------|
| Raw candidate rate        | ~200,000 H/s |
| Effective derivation rate | ~12,500 addr/s |

Raw rate is measured before the checksum prefilter. The prefilter rejects ~93.75% of candidates for 12-word phrases (~99.6% for 24-word) before PBKDF2 / BIP32 / secp256k1.

---

## Requirements

- Windows
- OpenSSL (libcrypto)
- libsecp256k1
- GCC (MSYS2 / MinGW-w64)

---

## Build

MSYS2 (UCRT64 shell):

```bash
pacman -S --needed \
  mingw-w64-ucrt-x86_64-gcc \
  mingw-w64-ucrt-x86_64-openssl \
  make git
