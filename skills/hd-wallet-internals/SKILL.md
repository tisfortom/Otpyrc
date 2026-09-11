---
name: hd-wallet-internals
description: Reconstruct an owner's HD wallet from a remembered or partial BIP-39 mnemonic (+ optional passphrase/25th word) via the exact standards their wallet used - BIP-39 seed, BIP-32 key tree, and BIP-44/49/84/86 / SLIP-0010 derivation paths. Use whenever you have a seed, mnemonic, xprv/xpub, or even a partial phrase and need to turn it into the full tree of the owner's addresses, or to figure out which derivation path/script type their wallet used.
---

# HD Wallet Internals (BIP-32/39/43/44/49/84/86)

This skill gives you the deterministic pipeline every hierarchical-deterministic
wallet runs: **words -> seed -> master key -> child keys -> addresses**. You will
know each standard by number, reproduce it byte-for-byte, and use the provided
scripts to derive an owner's entire address tree from whatever fragment they
have (full mnemonic, partial mnemonic, raw seed, or an extended key). It is the
central recovery path: get this exactly right and a remembered phrase becomes
the owner's wallet; get one constant wrong and you silently derive someone
else's empty wallet.

## Why this matters for the recovery project

The most likely thing the owner actually retained is a mnemonic — whole,
partial, or with an uncertain passphrase — because that is what every wallet
tells users to back up. Reconstructing their wallet from it, via *their* wallet's
exact standards, is the single highest-value recovery path. Everything else in
the curriculum (forensics, storage formats, GPU search) ultimately feeds a
correct HD derivation, and every result is verified by deriving to an address the
owner recognizes or that shows on-chain history. If the derivation is off by an
endianness, a salt string, or a path level, the whole search runs past the real
key.

## Prerequisites

Load these sibling skills first:

- `applied-cryptography` — HMAC, SHA-256/512, PBKDF2 (the KDFs used here).
- `elliptic-curve-cryptography` — secp256k1 point ops behind BIP-32 tweaks and
  the taproot key tweak; ed25519 for SLIP-0010.
- `encoding-address-formats` — Base58Check, bech32/bech32m, xpub/EIP-55 that turn
  a derived key into the address you match against.
- `blockchain-internals` — how to confirm which derived address actually holds
  the owner's funds.

Math threaded inline; go deeper in `math-number-theory-modular-arithmetic`
(mod-n key tweaks), `math-finite-fields-elliptic-curves` (the curve group), and
`math-probability-entropy-search` (sizing a word/passphrase search).

## Core concepts

**BIP-39 mnemonic.** Entropy `ENT in {128..256}` (mult. of 32) plus a checksum
of `ENT/32` bits (the top bits of `SHA-256(entropy)`) is chunked into 11-bit
words from a fixed **2048-word** list; `12/15/18/21/24` words carry
`128/160/192/224/256` entropy bits. Details: `references/bip39-mnemonics.md`.

**Mnemonic -> seed.** `seed = PBKDF2-HMAC-SHA512(NFKD(mnemonic), salt =
"mnemonic"+NFKD(passphrase), c=2048, dkLen=64)`. The wordlist and checksum are
*not* consulted here — a typo still yields a (wrong) seed. The passphrase is
salt, so there is no "wrong passphrase" error.

**BIP-32 master.** `I = HMAC-SHA512("Bitcoin seed", seed)`; left 32 bytes =
master private key (must be in `[1, n-1]`), right 32 = chain code.

**Child derivation.** For chain code `c_par`:
`I = HMAC-SHA512(c_par, data)` where `data = 0x00||ser256(k_par)||ser32(i)` for a
**hardened** index (`i >= 2^31`) or `serP(K_par)||ser32(i)` for a **normal**
index; then `k_i = IL + k_par (mod n)`, `c_i = IR`. **CKDpub** exists for normal
indices only (`K_i = IL*G + K_par`); hardened public derivation is impossible —
that is why account-level nodes are hardened. Full treatment + the 78-byte
xprv/xpub serialization: `references/bip32-derivation.md`.

**Paths (BIP-43/44).** `m / purpose' / coin_type' / account' / change /
address_index`. `purpose'` names the spec (44/49/84/86); `coin_type'` is
SLIP-0044 (BTC=0, ETH=60, testnet=1); `change` is 0 external / 1 internal.

**Script types.** Same key, four addresses: **BIP-44** legacy P2PKH (`1...`),
**BIP-49** P2SH-P2WPKH (`3...`), **BIP-84** native segwit P2WPKH (`bc1q...`),
**BIP-86** taproot P2TR (`bc1p...`). SLIP-0132 `ypub/zpub` prefixes signal the
script type in an exported account key. Details:
`references/derivation-paths-bip44-49-84-86.md`.

**SLIP-0010.** ed25519 chains (Solana `m/44'/501'/...`, Stellar `m/44'/148'/...`)
use a different master key string (`"ed25519 seed"`), **hardened-only**
derivation, and `k_i = IL` (replacement, not add). secp256k1 tooling does not
apply. Details: `references/passphrase-slip10-and-wallet-quirks.md`.

**Discovery.** Wallets stop scanning after a **gap limit** (default 20)
consecutive unused external addresses, then move to the next `account'`. Raise
the gap limit before concluding "no funds".

**Vendor quirks.** Ledger's ETH path increments `account'`
(`m/44'/60'/i'/0/0`), MetaMask/Trust increment `address_index`
(`m/44'/60'/0'/0/i`), and Electrum seeds are **not BIP-39** (salt `"electrum"`,
own wordlist, own version checksum). Full list:
`references/passphrase-slip10-and-wallet-quirks.md`.

## Hands-on

Run each script's built-in self-test first (no args), then use it:

1. **Seed from a mnemonic.** `python3 scripts/mnemonic_to_seed.py` (self-test
   asserts the Trezor vector). Then feed a candidate phrase + passphrase; add
   `--wordlist FILE` to also verify the BIP-39 checksum for the owner's language.
2. **Derive the tree.** `python3 scripts/bip32_derive.py <seed_hex> "m/84'/0'/0'/0/0"`
   prints chain code, pubkey, hash160, and the xpub/xprv. Self-test covers
   BIP-32 test vector 1 and CKDpriv/CKDpub consistency.
3. **Sweep unknown paths.** `python3 scripts/derivation_path_sweeper.py
   --mnemonic "<words>" [--passphrase P] --count 5` prints the first N addresses
   for BIP-44/49/84/86 (BTC) and MetaMask/Ledger (ETH) so you can match a
   remembered address. Self-test asserts the canonical BIP-84 and BIP-86
   addresses and the known ETH address for the test mnemonic — proof the seed,
   derivation, taproot tweak, bech32/bech32m, keccak-256 and EIP-55 are all
   correct end-to-end.

Exercises that build toward the project:
- Confirm the four script types give four different addresses from one seed;
  internalize why "the legacy address is empty" is not "no funds".
- Take an account `zpub` (BIP-84) and enumerate 20 receive addresses with
  CKDpub only — no private key — to locate funds watch-only.
- Given an 11-of-12 phrase with the last word missing, enumerate the ~128
  checksum-valid completions and derive each to the owner's known address.

## Recovery playbook hooks

A future agent mid-recovery should:

1. **Classify the input.** Full mnemonic? Partial? Raw seed? xprv/xpub? A
   `zpub`/`ypub` implies BIP-84/49. A phrase that fails every BIP-39 checksum may
   be Electrum or another scheme — load
   `references/passphrase-slip10-and-wallet-quirks.md`.
2. **Fix the KDF and curve.** BIP-39 (`salt="mnemonic"`) vs Electrum
   (`salt="electrum"`); secp256k1 (BIP-32) vs ed25519 (SLIP-0010). Wrong choice =
   wrong everything.
3. **Enumerate paths** with `scripts/derivation_path_sweeper.py`, ordered by the
   wallet the owner named (hand off large searches to
   `secret-search-orchestration` + `gpu-parallel-computing`).
4. **Prune with the checksum** for missing/typo'd words before any EC work
   (`math-probability-entropy-search`).
5. **Verify by derivation** to a known address / on-chain history
   (`blockchain-internals`, `crypto-correctness-testing`) — never by inspection.
6. **Raise the gap limit and scan change + multiple accounts** before reporting
   loss.

## Pitfalls & safety

- **Authorization.** This is self-recovery of the **owner's own** assets, with
  authorization. Deriving or scanning a phrase that is not the owner's is theft
  or surveillance. See `authorization-safety-opsec`.
- **Every derived xprv / private key / seed is live money.** Do the work
  **offline**, on an air-gapped machine; never send a seed, xprv, or derived key
  over the network, into a clipboard manager, or into a log. Keep secrets in
  wiped-on-drop memory (`secure-coding-secret-hygiene`, `rust-systems-programming`).
- **No error signal on wrong inputs.** A typo'd word or wrong passphrase yields a
  valid-looking wrong wallet. The only truth is matching a known address —
  always verify by derivation.
- **Byte-exactness.** Big-endian `ser256`/`ser32`, compressed `serP`, NFKD
  normalization, iteration count 2048, HMAC key strings (`"Bitcoin seed"` vs
  `"ed25519 seed"`). One mismatch silently corrupts the whole tree; guard with
  known-answer tests (`crypto-correctness-testing`).
- **Hardening asymmetry.** A non-hardened structure plus one child private key
  can leak the parent; know which levels the owner's wallet hardened before
  sharing any xpub.
- **Hard limits.** No seed/backup anywhere = **no recovery** (derivation cannot
  invent entropy). Keys generated inside a **Secure Enclave / secure element are
  non-extractable** even with full device access — confirm whether the app
  stored the seed (recoverable) or only the SE key (not) before promising a
  result (`ios-security-backup-keychain-forensics`).

## References

- `references/bip39-mnemonics.md` — entropy, checksum, PBKDF2 seed, languages,
  worked byte example.
- `references/bip32-derivation.md` — CKDpriv/CKDpub, chain codes, xprv/xpub
  serialization, fingerprints, test vector 1.
- `references/derivation-paths-bip44-49-84-86.md` — purpose/coin/account/change,
  SLIP-0044, script types, SLIP-0132 prefixes, gap limit.
- `references/passphrase-slip10-and-wallet-quirks.md` — passphrase search,
  ed25519 SLIP-0010, Electrum seeds, Ledger/MetaMask/Trust paths, hard limits.
- External specs: BIP-32, BIP-39, BIP-43, BIP-44, BIP-49, BIP-84, BIP-86
  (bitcoin/bips); SLIP-0010, SLIP-0044, SLIP-0132 (satoshilabs/slips); RFC 8018
  (PBKDF2), RFC 2104 (HMAC), FIPS 180-4 (SHA-2), RFC 8032 (Ed25519).
