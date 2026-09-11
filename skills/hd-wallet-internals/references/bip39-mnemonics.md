# BIP-39 Mnemonics: entropy, checksum, and the seed

Deep dive for turning an owner-remembered phrase into the exact 64-byte seed
their wallet used. Every constant here is load-bearing: a mismatch produces a
*different, valid-looking* seed and silently derives the wrong wallet.

## Contents
1. What BIP-39 actually specifies
2. Entropy -> words (the encoder)
3. The checksum (SHA-256 truncation)
4. Words -> seed (PBKDF2-HMAC-SHA512)
5. Wordlists and languages
6. Normalization (NFKD) traps
7. Worked byte-level example (12 words, all-zero entropy)
8. Recovery implications
9. Non-BIP-39 lookalikes to rule out

## 1. What BIP-39 actually specifies

BIP-39 defines two independent transforms:

- **entropy <-> mnemonic**: a reversible mapping between raw entropy plus a
  checksum and a sequence of words drawn from a fixed 2048-word list. This half
  needs the wordlist and is where the checksum lives.
- **mnemonic -> seed**: a one-way KDF from the *text* of the mnemonic (plus an
  optional passphrase) to a 512-bit seed. This half does **not** use the
  wordlist and does **not** check the checksum.

Critical consequence: `mnemonic_to_seed()` will happily hash a typo'd or
non-BIP-39 phrase into a seed. The checksum is only a *sanity gate* on the
encoder side; it is not enforced during seed derivation. Never assume a phrase
is valid because a seed came out.

## 2. Entropy -> words (the encoder)

Let `ENT` be the entropy length in bits. BIP-39 allows
`ENT in {128, 160, 192, 224, 256}`, always a multiple of 32.

- Checksum length `CS = ENT / 32` bits.
- Total bit string length `ENT + CS`, always a multiple of 11.
- Word count `MS = (ENT + CS) / 11`.

| ENT | CS | ENT+CS | words |
|-----|----|--------|-------|
| 128 |  4 |  132   |  12   |
| 160 |  5 |  165   |  15   |
| 192 |  6 |  198   |  18   |
| 224 |  7 |  231   |  21   |
| 256 |  8 |  264   |  24   |

Algorithm:
1. Generate `ENT` random bits.
2. `CS` = first `CS` bits of `SHA-256(entropy_bytes)`.
3. Concatenate `entropy_bits || checksum_bits`.
4. Split into 11-bit groups; each group (0..2047) indexes the wordlist.

Each word therefore carries exactly 11 bits. 12 words = 132 bits of which 128
are entropy (~128-bit security) and 4 are checksum.

## 3. The checksum (SHA-256 truncation)

The checksum is the **most significant `ENT/32` bits** of the SHA-256 digest of
the raw entropy bytes. For 12 words that is a single nibble (4 bits): only 1 in
16 random 12-word phrases passes. For 24 words it is a full byte: 1 in 256.

This is a cheap, powerful filter during a word-search recovery: enumerate
candidate last words / candidate slots, keep only those whose recomputed
checksum matches, and you discard 15/16 (12-word) or 255/256 (24-word) of the
space *before* any expensive EC derivation. See sibling skill
`math-probability-entropy-search` for sizing the surviving space and
`secret-search-orchestration` for ordering candidates.

Note: because the last word packs `(11 - CS)` entropy bits plus `CS` checksum
bits, not every wordlist word is a legal final word for a given prefix. For a
12-word phrase the final word has 7 free entropy bits + 4 checksum bits, so of
2048 words only 2048/16 = 128 are valid completions of any fixed first-11-word
prefix.

## 4. Words -> seed (PBKDF2-HMAC-SHA512)

    seed = PBKDF2(PRF   = HMAC-SHA512,
                  password = NFKD(mnemonic),          # the joined words
                  salt     = NFKD("mnemonic" + passphrase),
                  c        = 2048,                    # iterations
                  dkLen    = 64)                      # bytes (512 bits)

Invariants that must match byte-for-byte:
- PRF is **HMAC-SHA512** (not SHA256, not scrypt).
- Iteration count is exactly **2048**.
- Output is **64 bytes**.
- The literal salt prefix is the ASCII string `"mnemonic"`; the optional
  passphrase (BIP-39's "25th word") is appended directly with no separator.
- Empty passphrase => salt is exactly `"mnemonic"`.

The passphrase is *not* mixed like a password check; it is salt. There is no
"wrong passphrase" error — every passphrase yields a different valid wallet.
This is why a forgotten passphrase is a search problem, not a lockout. See
`passphrase-slip10-and-wallet-quirks.md`.

`scripts/mnemonic_to_seed.py` implements exactly this. Underlying math (HMAC,
PBKDF2) is covered in sibling skill `applied-cryptography`.

## 5. Wordlists and languages

- Each language wordlist has exactly **2048** entries.
- English is the interoperable default and the only list many wallets support.
- In the English list every word is uniquely identified by its **first four
  letters** (design property of the list) — useful when a photo of a backup is
  smudged.
- Words are sorted, enabling binary search for the index.
- The checksum is computed over the entropy *bytes*, independent of language;
  but the seed depends on the exact word *text*, so a phrase encoded in the
  Japanese list yields a different seed than the "same" entropy in English.
- Japanese and Korean lists use ideographic space / normalization subtleties;
  always NFKD-normalize (Section 6).

Do not hardcode a wordlist you cannot verify. If you need to check a checksum,
load the real list for the language the owner used and confirm it has 2048
entries (the script enforces this).

## 6. Normalization (NFKD) traps

Both the mnemonic and passphrase MUST be Unicode-normalized to **NFKD** before
hashing. Common failure modes when recovering from a human transcription:

- A passphrase typed with a composed accented character (NFC) hashes
  differently from the decomposed (NFKD) form. BIP-39 mandates NFKD.
- Non-breaking spaces or full-width spaces between words must collapse to a
  single ASCII space after normalization.
- Trailing whitespace / a stray newline from a text file changes the seed.
  Normalize and re-join on single spaces (the script does `" ".join(split())`).

## 7. Worked byte-level example (12 words, all-zero entropy)

Entropy (128 bits): `00000000000000000000000000000000`

    SHA-256(entropy) = 374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb
    first CS=4 bits = top nibble of the first byte 0x37 -> 0011

Compute precisely: `0x37 = 0011 0111`, the top 4 bits are `0011`. So the 132-bit
string is 128 zero bits followed by `0011`. Split into eleven-bit groups:
the first eleven groups are all `00000000000` = index 0 = **"abandon"**; the
last group is `0000000` (7 zero entropy bits) `0011` (checksum) = binary
`00000000011` = decimal 3 = wordlist index 3 = **"about"**.

Result: `abandon abandon abandon abandon abandon abandon abandon abandon
abandon abandon abandon about`.

Seed with passphrase `"TREZOR"`:

    PBKDF2-HMAC-SHA512("abandon ... about", "mnemonicTREZOR", 2048, 64) =
    c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553
    1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04

This is the canonical Trezor vector; `scripts/mnemonic_to_seed.py --selftest`
asserts it. The resulting BIP-32 master xprv is
`xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF`
(derive it with `scripts/bip32_derive.py <seed_hex> m`).

## 8. Recovery implications

- **One wrong/missing word**: use the checksum + known-good words. For a single
  unknown word in a 12-word phrase, at most 2048 candidates, of which ~128 pass
  checksum; each survivor is fully derivable and testable by matching a known
  address. For two unknowns the space is ~2048^2 pre-checksum; the checksum cuts
  it by 16x. Size it with `math-probability-entropy-search`.
- **Unknown word order**: 12! is ~4.8e8 permutations — feasible with checksum
  pruning + a target address; 24! is not, so lean hard on any structure the
  owner remembers.
- **Unknown passphrase**: cannot be checksum-pruned (it is salt); must be
  searched by deriving to a known address. Offload to GPU (`gpu-parallel-
  computing`) via `secret-search-orchestration`.
- **Verification is by derivation**, never by "does it look right": derive the
  candidate to the owner's known address/xpub and compare (`crypto-correctness-
  testing`, `blockchain-internals`).

## 9. Non-BIP-39 lookalikes to rule out first

If the checksum never validates against the English list, the phrase may not be
BIP-39 at all:

- **Electrum seeds** use a version-string HMAC scheme and their own KDF salt
  (`"electrum"`), not a BIP-39 checksum. A valid Electrum seed will *fail* the
  BIP-39 checksum by design. See `passphrase-slip10-and-wallet-quirks.md`.
- **Monero / 25-word** mnemonics are a different scheme (CRC-32 checksum word,
  1626-word list) entirely.
- **13/25-word** counts are not BIP-39 (12/15/18/21/24 only); 25 words usually
  means Monero or a BIP-39 phrase plus a written-down passphrase.

## References
- BIP-39 (mnemonic code for generating deterministic keys), bitcoin/bips.
- PBKDF2: RFC 8018 (PKCS #5 v2.1). HMAC: RFC 2104. SHA-512: FIPS 180-4.
- Sibling skills: `applied-cryptography`, `math-probability-entropy-search`,
  `encoding-address-formats`.
