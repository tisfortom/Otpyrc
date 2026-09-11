# Passphrases, SLIP-0010 (ed25519), and per-wallet quirks

Where real wallets diverge from the clean BIP-39/32/44 picture: the optional
passphrase, the ed25519 derivation used by Solana/Stellar/Cardano-family
wallets, non-BIP-39 Electrum seeds, and vendor path defaults. Getting these
wrong is the usual reason a correct seed still "finds nothing".

## Contents
1. The passphrase / "25th word"
2. SLIP-0010: ed25519 and NIST P-256 derivation
3. Electrum seeds (not BIP-39)
4. Vendor path quirks (Ledger, MetaMask, Trust, Trezor, Coldcard)
5. Hard limits: what is genuinely unrecoverable

## 1. The passphrase / "25th word"

BIP-39's optional passphrase is appended to the KDF salt
(`"mnemonic" + passphrase`, see `bip39-mnemonics.md`). Properties that drive
recovery strategy:

- It is **salt, not a password**: there is no stored verifier and no "wrong
  passphrase" signal. Every passphrase yields a *different, fully valid* wallet
  ("plausible deniability" / hidden wallets). The empty passphrase is itself a
  valid wallet distinct from any non-empty one.
- Therefore it **cannot be checksum-pruned**. The only test is: derive with the
  candidate passphrase down the owner's path and compare against a known
  address or xpub. This is a pure search over the passphrase space and belongs
  on GPU when large (`gpu-parallel-computing`, `secret-search-orchestration`).
- Vendors label it differently: Trezor "passphrase" / "hidden wallet", Ledger
  "passphrase attached to a second PIN", Coldcard "BIP-39 passphrase". They are
  the same BIP-39 salt mechanism.
- Normalization applies: NFKD the passphrase before hashing; a composed vs
  decomposed accent, or a trailing space, changes the wallet.

Search priors that help: length the owner recalls, a known base word with
digit/case variants, a date format, keyboard-adjacent typos. Enumerate by
descending prior; each candidate costs one PBKDF2(2048) + a short derivation.

## 2. SLIP-0010: ed25519 and NIST P-256 derivation

BIP-32 is secp256k1-specific (it relies on `k_i = IL + k_par mod n` and point
addition). Chains on **ed25519** (Solana, Stellar, Polkadot-family,
Cardano's simpler wallets, Near, Aptos, Sui) or **NIST P-256** use **SLIP-0010**
instead. Differences that matter:

- Master: `I = HMAC-SHA512(key = "ed25519 seed", data = seed)` — the HMAC key
  string is curve-specific. `IL` = private key, `IR` = chain code. For ed25519
  *any* 32-byte `IL` is a valid key, so there is no `IL >= n` retry.
- **ed25519 supports hardened derivation only.** Every index must be
  `>= 2^31`. There is no CKDpub and no normal-child derivation, because ed25519
  scalars are clamped and not additively homomorphic the way secp256k1 keys are.
- Child: `I = HMAC-SHA512(key = c_par, data = 0x00 || ser256(k_par) ||
  ser32(i))`, then `k_i = IL` (a **replacement**, not `IL + k_par`), `c_i = IR`.
- Public key: derive per RFC 8032 (Ed25519) from `k_i`; SLIP-0010 represents the
  serialized public key as `0x00 || A` (a leading zero byte before the 32-byte
  compressed point).

Common ed25519 paths (all levels hardened):
- Solana: `m/44'/501'/account'/0'` (Phantom uses `m/44'/501'/i'/0'`; some older
  tools used `m/44'/501'/0'`). SLIP-0044 coin type for Solana is 501.
- Stellar: `m/44'/148'/account'`.
- Because these are all-hardened and use a different curve, `bip32_derive.py`
  (secp256k1) does **not** apply; use a SLIP-0010 implementation and the chain's
  own address encoding. State the curve explicitly before deriving — mixing
  secp256k1 and ed25519 silently yields garbage. Curve details:
  `elliptic-curve-cryptography`.

## 3. Electrum seeds (not BIP-39)

Electrum (v2+) does **not** use BIP-39. Signs you have an Electrum seed: the
phrase fails the BIP-39 checksum against every language list, and the owner used
Electrum.

- **Version detection**: Electrum computes
  `HMAC-SHA512(key = "Seed version", msg = normalized_mnemonic)` and inspects the
  hex prefix of the digest: prefix `01` = Standard (legacy P2PKH), `100` =
  SegWit, `101` = 2FA. The seed is "valid" iff that prefix matches — this
  replaces BIP-39's SHA-256 checksum entirely. (Treat the exact prefix bytes as
  version-dependent; confirm against the Electrum source for the owner's
  version rather than hardcoding.)
- **Seed -> master seed**: `PBKDF2-HMAC-SHA512(mnemonic, salt = "electrum" +
  passphrase, c = 2048, dkLen = 64)`. Note the salt prefix is `"electrum"`, not
  `"mnemonic"` — so the same words give a *different* seed than BIP-39 would.
- **Wordlist** is Electrum's own list, not the BIP-39 English list.
- **Paths**: legacy standard wallets derive at `m/0/i` (receive) and `m/1/i`
  (change) directly under the master — **no** BIP-43 purpose level. SegWit
  standard wallets use a hardened account, e.g. `m/0'/0/i` and `m/0'/1/i`.
- Old Electrum v1 seeds are a different, pre-BIP-32 scheme again (a hex-stretched
  seed, `m/0` chains); rare but exists.

If the owner's phrase is Electrum, none of the BIP-39/44 machinery applies as-is;
reproduce Electrum's KDF and paths. Reverse the exact version from the app if
needed (`reverse-engineering`).

## 4. Vendor path quirks

All of the following are BIP-39/BIP-32 (secp256k1) wallets; the trap is the
**path**, not the KDF.

**Ledger (Ledger Live).** Bitcoin: standard BIP-44/49/84/86. Ethereum: Ledger
Live default is `m/44'/60'/i'/0/0` — it increments the **account'** level per
"account", *not* the address_index. This differs from MetaMask's
`m/44'/60'/0'/0/i`. Historic "Ledger (legacy)" import paths seen in MEW/MyCrypto
include `m/44'/60'/0'/i` (missing the change level) and `m/44'/60'/0'`. If ETH is
"missing" from a Ledger seed, sweep all three shapes — this is the single most
common Ledger recovery miss.

**MetaMask.** BIP-39 (12 words by default). Ethereum path `m/44'/60'/0'/0/i`,
incrementing address_index for additional accounts. Imported private keys are
stored outside the HD tree. Its vault is an encrypted keystore
(`wallet-storage-formats`).

**Trust Wallet.** BIP-39, standard BIP-44 per coin: ETH `m/44'/60'/0'/0/i`, BTC
defaults to native segwit `m/84'/0'/0'/0/i` in recent versions.

**Trezor / Suite.** BIP-39 + optional passphrase; standard BIP-44/49/84/86 for
BTC and `m/44'/60'/0'/0/i` for ETH. The passphrase creates fully separate hidden
wallets (Section 1).

**Coldcard.** BIP-39 + optional passphrase; standard BIP-84 default for BTC.

**Cardano (Yoroi/Daedalus).** Uses CIP-1852 / Ed25519-BIP32 (Icarus/Byron),
which is *neither* plain BIP-32 nor plain SLIP-0010 — a distinct scheme. If the
owner used Cardano, do not assume SLIP-0010; reproduce CIP-1852 specifically.

When the vendor is unknown, `scripts/derivation_path_sweeper.py` covers the
common BTC and ETH templates including the Ledger-legacy ETH shape; extend its
`TEMPLATES` list for anything exotic and confirm by deriving to a known address.

## 5. Hard limits: what is genuinely unrecoverable

State these plainly to the owner; effort spent against them is wasted.

- **No seed and no backup = no recovery.** HD keys are deterministic only from
  the seed (and passphrase). If the mnemonic, an encrypted keystore/vault, a
  raw private key, or an extended key never existed outside a device that is now
  gone, there is nothing to reconstruct. Derivation cannot invent entropy.
- **Secure Enclave / StrongBox / hardware-backed keys are non-extractable.**
  When a key was generated *inside* an Apple Secure Enclave, Android StrongBox,
  or a hardware wallet's secure element, the private key never leaves the chip
  and cannot be read out even with full device access
  (`ios-security-backup-keychain-forensics`). Some wallet *apps* store the actual
  seed in the keychain/keystore (recoverable) while only *gating* it behind SE
  biometrics; others put the key material itself in the SE (not recoverable).
  Determine which before promising anything — reverse the app if needed.
- **A forgotten strong passphrase over a high-entropy seed** may be
  computationally infeasible to search (that is the feature). Size it honestly
  with `math-probability-entropy-search` before committing GPU time.
- **A truly random, fully forgotten 24-word seed** is unrecoverable by design
  (256-bit space). Recovery only works when the owner remembers or has stored
  enough structure to bound the search.

Everything in this skill is for **self-recovery of the owner's own assets, with
authorization**. See `authorization-safety-opsec`.

## References
- SLIP-0010 (universal HD derivation over ed25519 / NIST P-256 / secp256k1),
  satoshilabs/slips. RFC 8032 (EdDSA / Ed25519).
- Electrum documentation and source (seed versioning, KDF salt "electrum").
- BIP-39 passphrase section; CIP-1852 (Cardano) for the exception noted.
- Sibling skills: `elliptic-curve-cryptography`, `wallet-storage-formats`,
  `ios-security-backup-keychain-forensics`, `secret-search-orchestration`,
  `math-probability-entropy-search`, `authorization-safety-opsec`.
