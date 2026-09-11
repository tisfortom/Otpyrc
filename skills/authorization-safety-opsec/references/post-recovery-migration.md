# Post-Recovery: Backup, Verify-by-Derivation, Migrate, Erase

> For the operator's own recovered assets only. The moment a real seed/key becomes plaintext is the highest-risk moment of the whole project — now there is spendable value in the clear. This file is the fixed procedure for that moment. Follow it in order; do not skip ahead to "check the balance online" or "move the funds."

## Table of contents
1. Why a recovered secret is "burned"
2. Step 1 — redundant offline backup FIRST
3. Step 2 — verify by offline derivation (not by spending)
4. Step 3 — migrate to a fresh wallet
5. Step 4 — secure erasure
6. Ordering invariants and failure handling
7. Threats specific to this phase

## 1. Why a recovered secret is "burned"

A secret you had to *recover* has, by construction, an **unknown exposure history**: it was lost, it may have been typed into unknown software, photographed, synced, or touched by malware in a past life, and you just handled it on a machine and possibly searched for it across a large candidate space. You cannot prove it was never exposed. Therefore the correct disposition is: use it exactly once, to move the funds to a **new** secret generated cleanly, then treat the recovered secret as compromised. Recovering funds and leaving them under the old, exposure-unknown key is the second-most-common way people lose recovered coins (the first is losing the recovered secret before backing it up).

## 2. Step 1 — redundant offline backup FIRST

Before deriving, before checking a balance, before anything: **durably record the recovered secret on at least two independent offline media.** A secret that exists only in RAM is one crash, one power blip, one fat-fingered wipe away from being lost again — this time for good.

- **Media:** paper is acceptable short-term; **metal** (stamped/engraved seed plates) survives fire/water and is preferred for anything you will hold. Two copies minimum, ideally **geographically separated** (defeats a single fire/flood/theft).
- **What to record:** the mnemonic words *in order* with their index numbers, the wallet type/derivation standard if known (e.g., BIP-84 native segwit vs BIP-44 legacy — the words alone do not encode the account path), and whether a BIP-39 **passphrase** ("25th word") is in use. Record the passphrase *separately* from the words if you use one — together on one medium they are a single point of compromise; apart, an attacker needs both.
- **No digital copies.** No photo, no text file, no password manager entry, no cloud. The backup is physical and offline.
- **Verify the backup is readable** (re-read it, confirm the checksum — a BIP-39 mnemonic's last word encodes a checksum, so a mistranscription is detectable; see `math-probability-entropy-search` and `hd-wallet-internals`) before you rely on it.

Only once a redundant, verified offline backup exists do you proceed.

## 3. Step 2 — verify by offline derivation (not by spending)

Confirm the recovered secret controls the expected asset **without touching the network with the secret and without broadcasting anything.**

- **Derive the address offline** from the secret and match it to an address the operator recognizes (from their records/ownership evidence). Derivation is public-key math: seed → BIP-32 master key → child key → public key → address. It never needs the network and never reveals the private key.
- **Get the path right.** The same seed produces *different* addresses under different derivation standards and account/change/index paths (BIP-44 `m/44'/0'/0'/0/0`, BIP-49 `m/49'/…` wrapped-segwit, BIP-84 `m/84'/…` native segwit, BIP-86 `m/86'/…` taproot, and coin type 60' for Ethereum). If the derived address does not match, try the standards the wallet in question used *before* concluding the secret is wrong — a path mismatch looks identical to a wrong key. `hd-wallet-internals` and `encoding-address-formats` own this; `crypto-correctness-testing` proves the derivation with known-answer vectors.
- **Confirm balance with the PUBLIC address only,** and preferably from a *separate* online machine (not the one that held the secret). Query the address, never the key. Mind privacy: querying many derived addresses at a third-party explorer links them; prefer your own node or a privacy-preserving path (`blockchain-internals`).
- **Do not "test" by sending a transaction from the old key** unless migration itself requires it — broadcasting leaks intent and timing, and a watcher/sweeper bot may race you (see §7).

Verification by derivation is also your correctness check: if the math is wrong (endianness, curve params, path), you catch it here as a mismatch instead of funding a wrong "recovered" address you can never spend.

## 4. Step 3 — migrate to a fresh wallet

- **Generate a new seed on a clean device** — a hardware wallet or a clean, offline install — with good entropy. Back *it* up redundantly (§2 discipline) before using it.
- **Send the funds from the recovered wallet to the new wallet.** This is the one time you use the recovered secret to sign. Do it on the offline machine if it can construct+sign the transaction offline (PSBT) and broadcast the signed transaction from a separate online machine; or use a hardware wallet fed the recovered seed *once*, understanding it is now burned.
- **Fees & UTXO care (BTC):** consolidate sensibly; set a fee that will confirm without overpaying; for large sums, consider a small test send first — but weigh that against tipping off a sweeper (§7).
- **Account model (ETH/EVM):** move native balance *and* tokens/NFTs; remember tokens are separate contract balances, and you need gas in the account to move them. Approvals granted by the old account do not follow the funds — the new account starts clean (good).
- **After migration, the recovered secret is dead.** Do not reuse it, do not keep it "just in case" beyond confirming settlement — its whole value is discharged into the new wallet.

## 5. Step 4 — secure erasure

Once the migration transaction has **confirmed/settled** (enough confirmations for BTC; finality for the EVM chain):

- **Zeroize** in-process secret buffers (compiler-non-elidable wipe — `secure-coding-secret-hygiene`).
- **Discard transient storage:** unmount and drop the `tmpfs`; power off an amnesic OS so RAM state is gone.
- **Sanitize any persistent residue** per NIST SP 800-88 Rev. 1: cryptographic erase (destroy the FDE key) for the working disk; for SSD/flash use the device sanitize/secure-erase or physical destruction (wear-leveling defeats naive overwrite); destroy single-use media that held plaintext.
- **Keep only:** the redundant offline backups of the **new** wallet, and the provenance log (which contains addresses and hashes, never secrets).
- **Do not erase the old *ciphertext/backup* prematurely** if there is any chance you missed a sub-account or a second wallet on the same seed — confirm you migrated everything first. Erase the working *plaintext*; retain the source *evidence* per your forensic/legal needs.

## 6. Ordering invariants and failure handling

The order is not negotiable, because each step guards the next:

```
BACKUP  →  VERIFY  →  MIGRATE  →  ERASE
(before you can lose it) (before you fund a wrong addr) (before you relax) (before you reconnect/discard)
```

- **If backup fails** (bad metal stamp, unreadable): re-record before doing anything else. Never advance on a single unverified copy.
- **If verification mismatches:** assume *path/standard* error first, then transcription, then wrong key. Re-derive across standards; re-check the mnemonic checksum. Do not fund the mismatched address.
- **If migration fails/stalls** (stuck tx): do not panic-broadcast conflicting transactions from a possibly-watched key; use fee-bumping (RBF/CPFP for BTC) deliberately.
- **If exposure is suspected at any point** (a stray network event, unknown software touched the seed): treat as compromised and migrate *immediately*, racing any potential sweeper — get funds to the fresh wallet first, investigate after.

## 7. Threats specific to this phase

- **Sweeper bots on exposed keys.** If the recovered key was ever exposed (and you must assume it might have been), a bot may be watching its addresses and will attempt to sweep any incoming funds — which is exactly why you *move funds out*, not in, and why a "test deposit" to the old key is dangerous. For a compromised key with a balance, migration is a race: broadcast the sweep-to-new-wallet with adequate fee, ideally via a private mempool path if the value justifies it.
- **Address-swap malware** on the machine you broadcast from can replace the *destination* (your new wallet) with the attacker's. Verify the destination address on the *new wallet's own trusted display* character-by-character (not just first/last), and consider a small verified test send for large migrations.
- **Fake "release fee" prompts / scam support.** No legitimate step here asks you to pay a stranger or send your seed anywhere — that is fraud (`scope-and-refusal-rules.md` §8).
- **Losing the new backup.** The migration only helps if the *new* seed is backed up redundantly and offline before funds arrive. Apply §2 discipline to the new wallet.

## Hard limits (state plainly, do not over-promise)

- If there is **no seed and no surviving ciphertext/backup**, there is nothing to migrate — a strong key with no stored copy is unrecoverable.
- A **Secure Enclave / StrongBox** key cannot be extracted to migrate; if the funds are behind such a key with no separate seed backup, recovery must come from that separate backup or not at all (`ios-security-backup-keychain-forensics`).
- An **address does not yield its key** (secp256k1 discrete-log hardness, `elliptic-curve-cryptography`) — you cannot "migrate" funds whose key you never recovered.

---

Cross-references: derivation in `hd-wallet-internals` + `encoding-address-formats`; correctness proofs in `crypto-correctness-testing`; erasure in `offline-key-handling.md` §10 and NIST SP 800-88 Rev. 1; chain checks in `blockchain-internals`.
