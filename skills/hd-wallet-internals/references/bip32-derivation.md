# BIP-32: HD key trees over secp256k1

Deep dive on the child-key derivation function, chain codes, extended-key
serialization, and the invariants that keep a derived key valid. Wrong
endianness, a dropped chain code, or serP-vs-ser256 confusion silently yields a
different tree.

## Contents
1. Objects in the tree
2. Master key from seed
3. CKDpriv (private -> private child)
4. CKDpub (public -> public child) and why hardening exists
5. serP / ser256 / ser32 (the byte encoders)
6. Extended key serialization (78 bytes) + Base58Check
7. Fingerprints and identifiers
8. The negligible-failure indices
9. Worked example (BIP-32 test vector 1)
10. Recovery implications

## 1. Objects in the tree

An extended key is `(key, chain_code)` where the chain code is 256 bits of
extra entropy that makes each node's children unpredictable without it.

- Extended private key: `(k, c)`, `k` a 256-bit scalar in `[1, n-1]`.
- Extended public key: `(K, c)`, `K = k*G` (a secp256k1 point).

`n` is the secp256k1 group order
`0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`.
Curve/field math and point ops are in sibling skill
`elliptic-curve-cryptography`; modular arithmetic in
`math-number-theory-modular-arithmetic` and `math-finite-fields-elliptic-curves`.

## 2. Master key from seed

Given the BIP-39 seed `S` (any length 16..64 bytes; BIP-39 gives 64):

    I  = HMAC-SHA512(key = "Bitcoin seed", data = S)
    IL = I[0:32]        # -> master private key k
    IR = I[32:64]       # -> master chain code c

- The HMAC *key* is the exact ASCII string `Bitcoin seed` (12 bytes). This
  constant differs per curve in SLIP-0010 (e.g. `ed25519 seed`); using the
  wrong one derives a valid-looking but wrong tree.
- If `IL == 0` or `IL >= n`, the seed is invalid (probability ~2^-127; never
  seen in practice). Reject rather than reducing mod n.

`scripts/bip32_derive.py: master_from_seed()` implements this.

## 3. CKDpriv (private parent -> private child)

Input: parent `(k_par, c_par)` and index `i` (0 .. 2^32-1).

    if i >= 2^31:                       # HARDENED
        data = 0x00 || ser256(k_par) || ser32(i)
    else:                               # NORMAL
        data = serP(point(k_par))  || ser32(i)   # 33-byte compressed pubkey
    I  = HMAC-SHA512(key = c_par, data = data)
    IL = I[0:32] ; IR = I[32:64]
    k_i = (parse256(IL) + k_par) mod n
    c_i = IR

- The HMAC *key* is the parent **chain code**, not the private key.
- Hardened uses the private key (prefixed with a `0x00` pad byte to 33 bytes);
  normal uses the compressed *public* key.
- The child scalar is `IL + k_par (mod n)` — a *tweak add*, not a replacement.
- `2^31 = 0x80000000` is the hardening threshold. Index `0'` means `0 + 2^31`.

## 4. CKDpub and why hardening exists

For **normal** indices only:

    data = serP(K_par) || ser32(i)
    I    = HMAC-SHA512(key = c_par, data = data)
    K_i  = point(parse256(IL)) + K_par          # EC point addition

This is the whole reason for hardening. Because the same `IL` appears in both
CKDpriv (`k_i = IL + k_par`) and CKDpub (`K_i = IL*G + K_par`), a public parent
plus a child *private* key leaks the parent private key:
`k_par = k_i - IL (mod n)`. Hardened derivation feeds the private key into the
HMAC so `IL` is unknowable from public data, and CKDpub is therefore
**impossible** for hardened indices (`i >= 2^31`). That is why account-level and
purpose-level nodes are hardened: an exported account `xpub` can enumerate
receive/change addresses (normal children) but cannot walk back up.

`scripts/bip32_derive.py` refuses hardened CKDpub and asserts the CKDpriv/CKDpub
consistency in its self-test.

## 5. serP / ser256 / ser32 (byte encoders)

- `ser32(i)`: 4-byte **big-endian** integer.
- `ser256(p)`: 32-byte **big-endian** integer (left-zero-padded).
- `serP(P)`: SEC1 **compressed** point = `0x02`/`0x03` (even/odd y) || `ser256
  (x)`, 33 bytes total. `0x04` uncompressed is *not* used inside BIP-32.

All big-endian. Ethereum and some blob formats use little-endian elsewhere —
mixing them is a classic silent-corruption bug (`crypto-correctness-testing`).

## 6. Extended key serialization (78 bytes) + Base58Check

Byte layout (then Base58Check with double-SHA-256 checksum -> the `xprv`/`xpub`
strings):

| bytes | field |
|-------|-------|
| 4  | version (see below) |
| 1  | depth (0x00 for master) |
| 4  | parent fingerprint (0x00000000 for master) |
| 4  | child number `ser32(i)` (0 for master) |
| 32 | chain code |
| 33 | key data: `0x00 || ser256(k)` for priv, or `serP(K)` for pub |

Version bytes (mainnet / testnet), BIP-32 core:

| string | hex | meaning |
|--------|-----|---------|
| xprv | `0x0488ADE4` | mainnet private |
| xpub | `0x0488B21E` | mainnet public |
| tprv | `0x04358394` | testnet private |
| tpub | `0x043587CF` | testnet public |

SLIP-0132 adds prefixes that *only* change these 4 version bytes to signal the
intended script type (yprv/ypub for BIP-49, zprv/zpub for BIP-84, and the
`Ypub`/`Zpub` multisig variants). They do **not** change the keys or the tree —
see `derivation-paths-bip44-49-84-86.md`. Base58Check itself is covered in
sibling skill `encoding-address-formats`; the 78-byte body plus 4-byte checksum
is 82 bytes, which Base58-encodes to the familiar 111/112-char string.

## 7. Fingerprints and identifiers

- **Identifier** of a node = `HASH160(serP(K)) = RIPEMD160(SHA256(serP(K)))`,
  20 bytes.
- **Fingerprint** = first 4 bytes of the identifier. Stored in a child's
  serialization as the parent fingerprint. It is a convenience/label only — not
  cryptographically binding; treat collisions as possible when matching.
- `scripts/bip32_derive.py` ships a from-scratch RIPEMD-160 (many Python builds
  drop `hashlib.new('ripemd160')`), self-tested against
  `RIPEMD160("") = 9c1185a5c5e9fc54612808977ee8f548b2258d31`.

## 8. The negligible-failure indices

In both CKDpriv and CKDpub, if `parse256(IL) >= n` — or in CKDpriv if the
resulting `k_i == 0` — the index is invalid and BIP-32 says to **skip to the
next index** `i+1`. Probability ~2^-127. A correct implementation must *not*
reduce `IL mod n` here (that would diverge from every reference wallet); it must
skip. The script raises so the caller advances the index.

## 9. Worked example (BIP-32 test vector 1)

Seed `000102030405060708090a0b0c0d0e0f`:

    m            xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi
    m (xpub)     xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8
    m/0'         xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7

`scripts/bip32_derive.py --selftest` asserts all three, plus that CKDpub on the
normal child `m/0'/1` matches CKDpriv-then-serialize-public.

## 10. Recovery implications

- If the owner kept an **account xpub** (e.g. exported from a watch-only setup),
  you can enumerate every receive/change address without the seed — enough to
  *locate* funds (`blockchain-internals`), though not to spend.
- A leaked `xpub` **plus** any one hardened-account child's private key does not
  break the parent (hardening); but a non-hardened structure plus a child priv
  key **does** — audit which levels the owner's wallet hardened.
- Reproduce the wallet's exact path *and* version bytes; a right tree read at
  the wrong path yields empty addresses and a false "no funds" conclusion.

## References
- BIP-32 (Hierarchical Deterministic Wallets), bitcoin/bips. Test vectors 1-5.
- SLIP-0132 (registered HD version bytes). SEC1 v2 (point encoding).
- Sibling skills: `elliptic-curve-cryptography`, `encoding-address-formats`,
  `math-number-theory-modular-arithmetic`, `crypto-correctness-testing`.
