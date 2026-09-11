---
name: authorization-safety-opsec
description: Load this FIRST and revisit at every step that touches a secret, a device, a backup, or a chain. Confirm the wallets, devices, and backups are the OWNER's own; record authorization; keep everything offline and air-gapped; and refuse or flag anything third-party or of unclear ownership. This is the framing every recovery, forensics, and reverse-engineering skill in this curriculum inherits.
---

# Authorization, Scope, Safety & Recovery OpSec

This skill is the constitution of the recovery project. It defines the single condition under which every other skill is allowed to run — that the target assets, devices, and backups belong to the operator (the person recovering) — and the operational hygiene that keeps recovery from becoming either theft or self-inflicted loss. Load it before anything else, keep it resident, and re-check it at every step that produces, moves, or reads a secret. If you cannot satisfy the ownership test, you stop: no derivation, no carving, no brute force, no device imaging.

The rest of the curriculum teaches how to reconstruct seeds, decrypt keystores, carve SQLite, and drive GPU search. This skill teaches *whether you are allowed to*, and *how not to lose the very secret you recover* to swap, a screenshot, a clipboard manager, or a "recovery service" scam. It is short on cryptographic novelty and long on discipline, because the failure modes it guards against are the ones that actually destroy funds or land people in legal trouble.

## Why this matters for the recovery project

The project is legitimate as exactly one thing: **self-recovery of the owner's own assets, with the owner's authorization.** The same techniques that reconstruct *your* forgotten passphrase would, pointed at someone else's backup, be unauthorized access to a computer and theft of the funds behind it. The cryptography does not know or care whose seed it is; the law and your conscience do. So the boundary cannot live in the tools — it has to live in a decision you make before you run them, recorded so you can prove it later.

There is also a purely selfish reason. The recovery pipeline handles live private keys in plaintext. A single leak — a key echoed to a log, a mnemonic that hit the pastebuffer, a core dump written to an unencrypted disk, a QR code caught by a cloud-synced screenshot — can hand your recovered funds to whoever is watching. Recovering a seed and then leaking it is worse than never recovering it, because now the funds move. OpSec is not paperwork bolted onto the real work; on a recovery machine it *is* the real work.

## Prerequisites

None. This is the root skill; load it before every other skill in the curriculum. It is a prerequisite *of*, not *on*, the others. In particular it front-loads:

- `secure-coding-secret-hygiene` — the code-level discipline (constant-time, no logging of secrets, `mlock`, wipe-on-drop) that implements this skill's memory rules.
- `operating-systems` — where secrets leak (swap, core dumps, hibernation, page cache) and how to lock and wipe memory.
- `digital-forensics-fundamentals` — reproducible, write-blocked handling of the owner's own devices and backups, and the chain-of-custody notes that make ownership provable.
- `secret-search-orchestration` — the brute-force engine whose every candidate must stay on the offline machine.
- `crypto-correctness-testing` — because an unauthorized *or* incorrect derivation both waste the one shot you get.

## Core concepts

### 1. The ownership test (necessary and sufficient gate)

Before any operation, all of the following must be true. If any is false or unknown, stop and flag.

1. **Asset ownership.** The wallet/address whose key you are reconstructing is controlled, or was controlled, by the operator. Evidence: prior spends the operator initiated, the device/backup was in the operator's sole possession, receipts/exchange withdrawals to the address, or the operator's own records.
2. **Device/backup ownership.** The phone, disk, `wallet.dat`, iOS backup, or keystore you read is the operator's own property or was created by them.
3. **Authorization is recorded.** The operator has written and signed a short authorization statement (see `references/authorization-record-template.md`) asserting 1 and 2 and the intent to recover *their own* funds. If you are an agent acting for the operator, this record is your license to proceed.
4. **No third-party secrets in scope.** The target does not include another person's keys, and the method will not read another person's data as a side effect (e.g., a shared backup, a multi-user disk image).

This is deliberately conservative. "I found this hardware wallet" is **not** ownership. "A friend asked me to get into their wallet" is **out of scope** for this curriculum regardless of good intentions — it is someone else's secret and someone else's legal exposure. The correct response there is refusal, not "authorization by proxy."

**Worked scoping example.** You have an old iPhone backup and remember the wallet held ~0.4 BTC you bought on an exchange in 2019. Ownership evidence: the exchange withdrawal record to an address, the backup was made on your own phone, you paid for the phone. This passes — proceed, recording that evidence in the authorization record. Now suppose the same backup also contains a *second* wallet app you do not recognize, tied to an account that was never yours (a household member restored onto this device once). That wallet is **out of scope**: do not derive its keys, do not scan its addresses, and note the boundary. Ownership is asserted per wallet/asset, not per device — one backup can straddle the line.

### 1a. Legal framing at the mechanism level

This is not jurisdiction-specific legal advice, but the shape is consistent across computer-misuse law: the crime is *access without authorization*, and *your own* system with *your own* data is authorized by definition. The US Computer Fraud and Abuse Act (18 U.S.C. § 1030) and the UK Computer Misuse Act 1990 both hinge on the authorization boundary, not on the technique. Reconstructing your own forgotten passphrase to your own encrypted file is not "unauthorized access"; running the identical code against someone else's backup is. This is why the ownership record matters even though no one may ever ask for it — it is the artifact that distinguishes the two identical-looking activities. When ownership is genuinely contested (divorce, estate, business dissolution, bankruptcy), the resolution is *legal*, not technical: get the authority in writing from whoever holds it before touching the bytes.

### 2. Refusal and flag rules

Encode these as hard stops, not warnings you can click through. See `references/scope-and-refusal-rules.md` for the full decision tree and worded responses.

- **Refuse** any target you cannot tie to the operator's ownership: found/purchased-with-coins-still-on-them devices, gifted-but-not-yet-owned wallets, "help me get into X's account," leaked seed lists, exchange-internal keys, or any request whose framing is access-for-someone-else.
- **Refuse** to exfiltrate: no uploading seeds/keys/ciphertext/dumps to any network service, pastebin, cloud drive, LLM API, or "online recovery tool," even to "just check the address."
- **Flag and pause** on ambiguity: shared/family devices, business/DAO/multisig funds where you are one of several controllers, inherited wallets without a clear legal chain, or anything where a second person could reasonably claim the coins. Ambiguity resolves *up* to a human decision, never *down* to "probably fine."
- **Refuse** to weaken the setup for convenience: no putting the seed on a networked machine "just this once," no online decryption of "just the header," no third-party brute-force service.

### 3. Offline / air-gapped workflow

The recovery machine that touches plaintext secrets must be offline and stay offline for the life of the material. See `references/offline-key-handling.md` for the build.

- **Physical air gap.** No Ethernet, Wi-Fi radio disabled or removed, Bluetooth off, no cellular. Preferred: a machine whose radios are physically absent or a live OS booted with networking disabled.
- **Ephemeral OS.** Boot a live, amnesic environment (e.g., a Tails-style read-only USB) so nothing persists to internal disk by default; or a machine with full-disk encryption whose disk you will later wipe.
- **No cloud anything.** No cloud clipboard, no photo cloud sync, no "find my device," no telemetry, no crash reporting. These are the invisible exfiltration channels.
- **Data crosses the gap on read-only media** (write-once optical, or a USB you treat as one-way) carrying only ciphertext and KDF parameters *into* the machine, and only derived *public* addresses *out*. Never carry a plaintext secret out of the air gap in the clear.
- **Trust the toolchain you carry in.** Pin and verify (hashes/signatures) the recovery binaries you bring across; a supply-chain-tainted tool on the air-gapped machine defeats the air gap.

### 4. Memory-, swap-, and disk-leak model

The OS is the second adversary. A secret in RAM can reach persistent storage through **swap/pagefile**, **hibernation image**, **core/crash dumps**, **page-cache-backed temp files**, and **the clipboard**. Concretely:

- Disable swap (`swapoff -a`) or use only encrypted swap; disable hibernation; set core dump limit to zero (`ulimit -c 0`) before running anything that holds a key.
- Hold secrets in `mlock`ed pages so they cannot be paged out; zeroize before free. This is what `secure-coding-secret-hygiene` and the Rust/C++ skills implement; this skill mandates it.
- Never place a plaintext secret in a normal file, a shell history line, an environment variable readable via `/proc`, or the clipboard. Prefer piping between processes over temp files; if a temp file is unavoidable, put it on a `tmpfs` (RAM-backed) mount, never on the encrypted disk's page-cache path, and wipe the tmpfs.
- **Screens and cameras are exfiltration channels too.** No screenshots of seeds/QRs (screenshot may cloud-sync); assume any on-screen secret can be shoulder-surfed or captured. Show the seed once, on the air-gapped display, to write it down.

### 5. Handling a recovered secret

The moment of recovery is the highest-risk moment, because now there is plaintext with real value. See `references/post-recovery-migration.md`.

- **Redundant, offline backups first.** Write the recovered seed/key to at least two durable offline media (paper/metal, ideally geographically separated) *before* doing anything else. A single medium is a single point of failure; funds recovered and then lost to a coffee spill are still lost.
- **Verify by derivation, not by spending.** Confirm the secret controls the expected address by deriving the address offline (public-key math only) and matching it — not by broadcasting a transaction that leaks intent. `hd-wallet-internals` + `encoding-address-formats` do the derivation; `crypto-correctness-testing` proves it byte-for-byte.
- **Migrate promptly to a fresh wallet.** A recovered secret has, by definition, an unknown exposure history — it was lost, searched for, possibly typed, possibly touched by malware in its past life. Generate a **new** seed on a clean device and move the funds to it. Treat the recovered key as burned the instant recovery succeeds.
- **Secure erasure.** After migration and confirmed settlement, wipe the working copies: zeroize RAM, destroy the tmpfs, and wipe or physically destroy any transient media that held plaintext. Keep only the deliberate offline backups of the *new* wallet.

### 6. Scam and malware threat model

Desperation is the attack surface. The ecosystem around lost crypto is dense with predators. See `references/scope-and-refusal-rules.md` (final section) for the catalog.

- **"Recovery services"** that ask for your seed, your ciphertext, an upfront fee, or remote access are theft. No legitimate process needs your seed sent anywhere. This curriculum's whole point is that *you* run the math offline.
- **Clipboard hijackers / address-swap malware** silently replace a copied address with the attacker's. On the air-gapped machine this is contained; the risk appears when you finally transact on an online machine — verify destination addresses character-by-character on a trusted screen, and use the fresh wallet's own display.
- **Fake wallet apps and trojaned tools** exfiltrate seeds on entry. Only run pinned, verified tooling on the air-gapped box; never enter a real seed into an app you have not vetted.
- **Coercion / "$5 wrench" and social engineering** are out of technical scope but in the threat model: keep the *existence* and *location* of recovered funds and backups need-to-know.

### 6a. Egress-channel inventory for the recovery machine

Treat "offline" as a property you must actively enforce against a long list of channels, not a default. Enumerate and kill each:

- **Radios:** Ethernet unplugged, Wi-Fi and Bluetooth disabled in firmware/OS (ideally hardware-removed), cellular/WWAN off, NFC off, UWB off.
- **Sync surfaces:** cloud clipboard, cloud photo/screenshot sync, notes/keychain sync, "find my device," browser profile sync, IDE/settings sync.
- **Telemetry:** OS crash/error reporting, application analytics, package-manager phone-home, update checks.
- **Removable-media autorun** and any daemon that indexes or thumbnails inserted media (it may copy previews off).
- **Peripheral bridges:** a phone tethering USB, a "smart" display, a KVM with network, a printer with Wi-Fi — each is a bridge across the gap.
- **The human channel:** photos of the screen, dictating a seed aloud near a voice assistant, typing it where an online machine can see the same keyboard (shared KVM). The gap is only as good as the weakest of these.

The mental model: a secret leaves the machine if *any* byte-carrying path reaches a network, and a screenshot on a sync-enabled OS is such a path even with every radio off, because the sync happens later when you (or the OS) reconnect. Default-deny; enumerate; verify.

### 7. Provenance and documentation

Recovery must be **reproducible and attributable to the owner**. Keep a contemporaneous log: what device/backup, acquired how and when, what you did, what you derived. This serves three ends at once — it is your authorization evidence (you can show the assets are yours), it is your forensic integrity record (hashes of images, so you can prove you did not alter anything), and it is your operational memory (so a search you pause can resume without re-deriving). `digital-forensics-fundamentals` supplies the hashing/imaging discipline; this skill supplies the ownership-and-intent header that sits on top of it.

## Hands-on

1. **Fill the authorization record.** Copy `references/authorization-record-template.md`, complete every field for your actual situation, and sign/date it. If you cannot honestly complete the ownership fields, that is the exercise telling you the target is out of scope.
2. **Run the pre-flight checklist.** Walk `references/offline-key-handling.md`'s checklist against your recovery machine: radios off, swap off, hibernation off, core dumps off, no cloud sync, tmpfs for transients, tooling hashes verified. Do not proceed until every box is checked.
3. **Trace the leak paths on your own box.** On a scratch VM, put a marker string in memory, then check whether it can reach disk: inspect swap, force a core dump, take a screenshot, copy it to the clipboard, and confirm where it landed. This makes the abstract leak model concrete before real secrets are involved.
4. **Rehearse the refusal tree.** Take the scenarios in `references/scope-and-refusal-rules.md` and, for each, decide refuse / flag / proceed and write the one-line justification. Recovery agents should be able to do this without hesitation.
5. **Dry-run the migration.** With a throwaway testnet key, practice: derive-to-verify offline, back up redundantly, migrate to a fresh key, then securely erase the working copy. The point is muscle memory for the real, high-stress moment.

## Recovery playbook hooks

A future agent mid-project uses this skill as the gate and the wrapper around every other action:

- **At project start:** load this skill, obtain/complete the authorization record (`references/ownership-and-authorization.md`, `references/authorization-record-template.md`), and stand up the offline machine (`references/offline-key-handling.md`). Nothing else runs until these are done.
- **Before each new target** (a new backup, device, keystore): re-run the ownership test (§1) and the refusal rules (§2). Ownership is per-target, not once-per-project.
- **Before any operation that materializes a secret** (decryption, mnemonic reconstruction, carving a private key, a GPU search hit): confirm the offline/leak controls (§3–§4) are active on the machine that will hold the plaintext.
- **On a hit:** switch to the post-recovery procedure (§5, `references/post-recovery-migration.md`) — back up, verify-by-derivation, migrate, erase — before celebrating or touching the network.
- **Throughout:** keep the provenance log (§7). Hand hashing/imaging to `digital-forensics-fundamentals`, memory hygiene to `secure-coding-secret-hygiene`, and correctness proofs to `crypto-correctness-testing`.

## Pitfalls & safety

- **Ownership is per-target and non-transferable.** "The project is authorized" does not authorize a *new* device that showed up mid-project. Re-test. And no one can authorize you onto *their* wallet through this curriculum — that is not self-recovery, and the answer is refusal.
- **The clipboard, screenshots, and cloud sync are the leaks people forget.** They feel innocuous precisely because they are so routine. Treat every one as a network egress.
- **Swap/hibernate/core-dump can defeat a perfect air gap** by writing plaintext to disk that outlives the session. Disable them *before* the key exists in memory, not after.
- **Recovering and then leaking is the worst outcome** — it converts "lost" into "stolen." Back up *before* you migrate, migrate *before* you relax, erase *before* you reconnect.
- **Hard limits — do not promise what physics forbids.** If there is no seed, no backup, and no surviving ciphertext, there is **no recovery**: a strong key with no stored copy is gone. **Secure Enclave / StrongBox-class keys are hardware-bound and non-extractable** — you cannot pull the private key off the chip, so recovery must come from a *separate* backup of the seed, never from the enclave itself (`ios-security-backup-keychain-forensics` details the boundary). An address alone does not yield its private key — that is the security assumption of `elliptic-curve-cryptography` (secp256k1's discrete-log hardness), and no amount of compute in this curriculum breaks it. State these limits plainly; do not let a desperate owner burn months chasing a sealed key.
- **Correctness is a safety property here.** An unauthorized derivation is a legal failure; an *incorrect* derivation is a financial one — it can send a GPU search past the real key, or produce a "recovered" address you fund and can never spend. Gate real runs behind `crypto-correctness-testing`.
- **When in doubt, stop and ask a human.** Ambiguity about ownership, scope, or exposure always escalates to a person; it never gets resolved by the tool proceeding.

## References

- `references/ownership-and-authorization.md` — the ownership test in depth: what counts as evidence of control, the legal framing of self-recovery vs. unauthorized access (CFAA/computer-misuse-class statutes, at a mechanism level, not jurisdiction-specific advice), and how authorization is recorded.
- `references/scope-and-refusal-rules.md` — the full refuse/flag/proceed decision tree, worded refusals, and the scam/malware catalog.
- `references/offline-key-handling.md` — building and operating the air-gapped recovery machine; the swap/hibernate/core-dump/clipboard leak model and the pre-flight checklist.
- `references/post-recovery-migration.md` — the moment-of-recovery procedure: redundant backups, verify-by-derivation, migrate-to-fresh, secure erasure.
- `references/authorization-record-template.md` — a fill-in authorization + provenance record you complete and sign before proceeding.
- External, at the mechanism level (verify current text before relying on specifics): computer-misuse statutes such as the US Computer Fraud and Abuse Act (18 U.S.C. § 1030) and the UK Computer Misuse Act 1990 criminalize *unauthorized* access — which is exactly what the ownership test keeps you outside of; NIST SP 800-88 Rev. 1 (media sanitization) for the erasure model; BIP-32/39/44 (via `hd-wallet-internals`) for verify-by-derivation.
