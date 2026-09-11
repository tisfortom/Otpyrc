# Derivation paths: BIP-43/44/49/84/86, SLIP-0044, gap limit

The tree from `bip32-derivation.md` is infinite; a *path convention* tells a
wallet which branch holds real funds and which address type each leaf encodes.
Reading the wrong convention makes the owner's funded branch look empty.

## Contents
1. BIP-43: the purpose level
2. BIP-44 five-level path
3. SLIP-0044 coin types
4. Change and address_index
5. Script types: BIP-44/49/84/86 side by side
6. SLIP-0132 xpub prefixes
7. Gap limit and account discovery
8. Enumeration strategy for recovery

## 1. BIP-43: the purpose level

BIP-43 reserves the **first** child level under the master as a hardened
`purpose'` that names the spec governing the rest of the path:

    m / purpose' / ...

`purpose` equals the BIP number: 44, 49, 84, 86. It is always hardened. A wallet
picks its purpose and everything below follows that spec's meaning.

## 2. BIP-44 five-level path

    m / purpose' / coin_type' / account' / change / address_index

- `purpose'` = 44' (or 49'/84'/86' for the segwit/taproot variants).
- `coin_type'` = SLIP-0044 registered index (hardened).
- `account'` = 0', 1', ... user-visible "accounts" (hardened).
- `change` = 0 (external/receive) or 1 (internal/change). **Not** hardened.
- `address_index` = 0, 1, 2, ... **Not** hardened.

The top three levels are hardened so an exported account `xpub`
(`m/purpose'/coin'/account'`) can generate all receive+change addresses
(normal children) without exposing sibling accounts or the master.

## 3. SLIP-0044 coin types

`coin_type'` is registered in SLIP-0044. Values that matter for recovery:

| coin | type | notes |
|------|------|-------|
| Bitcoin | 0 | mainnet |
| Testnet (all coins) | 1 | any testnet uses 1 |
| Litecoin | 2 | |
| Dogecoin | 3 | |
| Ethereum | 60 | and most EVM chains reuse 60 in practice |
| Ethereum Classic | 61 | |
| Bitcoin Cash | 145 | |

Do not invent coin types; if unsure, look up the exact SLIP-0044 value for the
owner's coin rather than guessing. Many EVM chains (Polygon, BSC, etc.) are used
by wallets under coin_type 60 with the same address, because they share the
Ethereum keyspace — so one derivation covers many chains
(`blockchain-internals`).

## 4. Change and address_index

- The **external chain** (`change=0`) holds addresses shown to receive funds.
- The **internal chain** (`change=1`) holds change outputs the wallet generates
  itself. Funds hide here constantly — always scan change chains too.
- Ethereum-style wallets typically use only `change=0` and increment
  `address_index`, because the account model has no change outputs.

## 5. Script types: BIP-44/49/84/86 side by side

The purpose determines the **address encoding** applied to the derived pubkey:

| BIP | purpose | path template | script | address example prefix |
|-----|---------|---------------|--------|------------------------|
| 44  | 44' | m/44'/0'/a'/c/i | P2PKH (legacy)          | `1...`  (base58) |
| 49  | 49' | m/49'/0'/a'/c/i | P2SH-P2WPKH (wrapped segwit) | `3...` (base58) |
| 84  | 84' | m/84'/0'/a'/c/i | P2WPKH (native segwit)  | `bc1q...` (bech32) |
| 86  | 86' | m/86'/0'/a'/c/i | P2TR (taproot, single key) | `bc1p...` (bech32m) |

Details of each encoding (base58check, bech32, bech32m, the taproot key tweak)
live in `encoding-address-formats`; `scripts/derivation_path_sweeper.py`
implements all four plus Ethereum EIP-55 and self-tests the canonical BIP-84 and
BIP-86 vectors end-to-end.

Key point: the **same private key** produces four *different* addresses under
these four conventions. A single seed can therefore have funds sitting at a
`bc1q...` address while its `1...` address is empty. "No funds" is only true
after sweeping every plausible script type.

## 6. SLIP-0132 xpub prefixes

Some wallets serialize the account extended pubkey with script-type-specific
version bytes (SLIP-0132), changing the human-readable prefix but not the key:

| prefix | script type | corresponds to |
|--------|-------------|----------------|
| xpub/xprv | legacy P2PKH | BIP-44 |
| ypub/yprv | P2SH-P2WPKH  | BIP-49 |
| zpub/zprv | native P2WPKH| BIP-84 |
| Ypub/Zpub | multisig variants | P2WSH-in-P2SH / P2WSH |

If the owner saved a `zpub...`, it is a BIP-84 account key. You can convert it to
a plain `xpub` by swapping only the 4 version bytes and re-Base58Check-encoding
(the 78-byte body is identical) — but keep track, because the prefix is your clue
to which address type to render.

## 7. Gap limit and account discovery

Wallets do not scan infinitely. BIP-44 defines a **gap limit** (default **20**):
scanning stops after 20 *consecutive* unused external addresses. Discovery:

1. For `account' = 0`: derive external addresses `0,1,2,...`; query each for any
   history. Stop after 20 consecutive with zero history.
2. If account 0 had any activity, repeat for account 1, and so on, stopping at
   the first account with an entirely unused external chain.

Recovery consequences:
- If the owner manually skipped ahead (generated address index 50 without using
  0..49), a strict gap-limit-20 scan **misses** it. When funds are "missing" but
  the seed is right, **raise the gap limit** (e.g. 100 or 1000) before concluding
  loss.
- Scan **both** `change=0` and `change=1`.
- Scan **multiple accounts**, not just account 0.

## 8. Enumeration strategy for recovery

When the wallet software/vendor is unknown, sweep the cross-product:

    purpose  in {44', 49', 84', 86'}          # script type
    coin     in the owner's plausible coins    # SLIP-0044
    account  in {0', 1', 2', ...}              # small range first
    change   in {0, 1}
    index    in {0 .. gap_limit}

`scripts/derivation_path_sweeper.py` runs this cross-product for the common
templates and prints every address so you can match against a remembered address
or an on-chain hit. Order candidates by prior probability (what wallet did they
say they used?) using `secret-search-orchestration`; confirm a hit by deriving
to a known address, never by eyeballing (`crypto-correctness-testing`).

Vendor-specific path quirks (Ledger's ETH accounts, Electrum's non-BIP-44 paths,
MetaMask/Trust defaults) are catalogued in
`passphrase-slip10-and-wallet-quirks.md`.

## References
- BIP-43 (purpose field), BIP-44 (multi-account hierarchy), BIP-49, BIP-84,
  BIP-86, bitcoin/bips.
- SLIP-0044 (coin types), SLIP-0132 (HD version bytes), satoshilabs/slips.
- Sibling skills: `encoding-address-formats`, `blockchain-internals`,
  `secret-search-orchestration`.
