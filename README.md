# bip39-template-finder

> **Recover your Bitcoin wallet.** Rebuild a forgotten or partially lost BIP39 seed phrase from a template and match it against your BTC address (hash160) using BIP44 / BIP49 / BIP84 derivation.

![platform](https://img.shields.io/badge/platform-Windows-blue)
![language](https://img.shields.io/badge/language-C-lightgrey)
![license](https://img.shields.io/badge/license-MIT-green)
![deps](https://img.shields.io/badge/deps-OpenSSL%20%7C%20libsecp256k1-orange)
![speed](https://img.shields.io/badge/speed-~200k%20H%2Fs%20%2F%2024%20threads-brightgreen)

---

## Recover your Bitcoin

Lost part of your seed phrase? Remember the first few words but not the rest? Typed a word wrong years ago and now can't restore your wallet?

`bip39-template-finder` is built exactly for that: you give it **what you remember** (as a template) and **your BTC address hash160**, and it brute-forces the missing words locally on your own machine until it finds the phrase that derives to your address.

- 12-word or 24-word phrases
- BIP44 (Legacy `1...`), BIP49 (SegWit `3...`), BIP84 (Native SegWit `bc1...`)
- Your seed never leaves your PC — no network, no telemetry, no cloud
- Works on CPU, scales with cores

> ⚠️ **Disclaimer** — this tool is intended for **recovering your own wallets**. Using it against wallets you do not own is illegal in most jurisdictions. The author is not responsible for any misuse.

---

## Speed test

Measured on **AMD Ryzen 9 3950X (16C / 32T)**, **24 threads**, `-ch 1000`, `-mode seq`, BIP84, 12-word template with 4 wildcards, Windows 10, MSVC `/O2`.

| Metric                                | Value                |
|---------------------------------------|----------------------|
| Threads                               | 24                   |
| Raw candidate rate                    | **~200,000 H/s**     |
| Checksum-valid rate                   | ~6.25% of raw        |
| PBKDF2 + BIP32 + secp256k1 per valid  | ~1 candidate / 50 µs |
| Effective full-derivation throughput  | ~12,500 addr/s       |
| Search space (4 wildcards, 2048 words)| 2048⁴ ≈ 1.76 × 10¹³  |
| Estimated full scan (24 threads)      | ~44 years            |

**Interpretation:** the 200k H/s figure is the **raw enumeration rate** — how many template combinations are tested per second *before* the checksum prefilter. Because the checksum prefilter rejects ~93.75% of candidates for 12-word phrases (and ~99.6% for 24-word), only a small fraction reaches the expensive PBKDF2 / BIP32 / secp256k1 pipeline.

The checksum prefilter is what makes CPU search viable: without it, throughput would collapse by 1–2 orders of magnitude.

Scaling is near-linear with physical cores up to the point where PBKDF2 latency and memory bandwidth become the bottleneck.

> Numbers are indicative. Your mileage will vary with template size, wildcard count, RAM speed, OpenSSL build, and background load.

---

## Overview

`bip39-template-finder` is a Windows command-line tool for **recovering your own BIP39 seed phrase** when you only remember part of it.

You provide:
- a **template** of the phrase where unknown words are replaced with `*`,
- a **wordlist** of candidate words to substitute into the `*` positions,
- the **target hash160** — the 20-byte hash of the public key, i.e. the payload of your BTC address.

The tool enumerates all combinations, filters them with a fast BIP39 checksum prefilter, derives the key along the configured BIP32 path, and compares the resulting hash160 with the target. On a match, the recovered mnemonic is written to a file.

---

## Features

- **Bitcoin-focused recovery** — BIP44 / BIP49 / BIP84 paths, ready for legacy, SegWit and native SegWit addresses.
- **Template-based search** — fix the words you remember, brute-force the rest with `*`.
- **12- and 24-word phrases.**
- **Precomputed checksum filter** — invalid mnemonics are rejected *before* the expensive PBKDF2 / BIP32 / secp256k1 work.
- **Multithreaded** — scales to any number of CPU cores (up to 1024 threads).
- **Two search modes:**
  - `seq` — deterministic full enumeration (stops at 100%).
  - `rnd` — infinite random search until a match is found.
- **Self-test** at startup (checksum + BIP84 hash160 for the standard `abandon ... about` vector).
- **Live progress** — processed count, valid count, speed, elapsed time.
- **Automatic output** — matched mnemonic is written to a file.
- **Fully offline** — no network access, no telemetry, no external services.

---

## Requirements

- **Windows** (uses Win32 threads).
- **OpenSSL** (libcrypto) — for SHA-256, RIPEMD-160, HMAC-SHA512, PBKDF2-SHA512.
- **libsecp256k1** — for EC public key derivation.
- A C compiler: **MSVC** or **MinGW-w64**.

---

## Build

### MSVC (Developer Command Prompt)

```bat
cl /O2 /W3 seedfinder.c ^
   /I C:\deps\openssl\include ^
   /I C:\deps\secp256k1\include ^
   /link /LIBPATH:C:\deps\openssl\lib ^
         /LIBPATH:C:\deps\secp256k1\lib ^
         libcrypto.lib libsecp256k1.lib
