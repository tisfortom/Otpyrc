# Authorization & Provenance Record — fill-in template

> Complete this **before** touching any secret, device, backup, or chain data, and re-complete the per-target sections for every new target. It is your authorization evidence, the header of your forensic provenance log, and your scope contract with yourself. It contains **no secrets** — never write a seed, private key, passphrase, or PIN into this record.

How to use: copy the block below into a plain-text file kept *with the project* (not with the secrets). Fill every field. Sign and date contemporaneously. If you cannot honestly complete the ownership fields, the target is out of scope — stop (see `scope-and-refusal-rules.md`).

---

## A. Operator / authorization

```
Record ID:                 __________________________   (unique per project)
Date/time (contemporaneous): _______________________    (ISO 8601, with timezone)
Operator name:             __________________________
Operator role:             [ ] I am the owner   [ ] I am authorized by the owner (attach authority)
If authorized-by-owner:
  Owner name:              __________________________
  Nature of written authority: ______________________  (e.g., signed letter, court order, executor grant)
  Authority reference/ID:  __________________________
Assertion (initial):  I assert that the target(s) below, and the value they control,
  are the owner's own property, and that I am recovering the owner's own funds.  ____ (initials)
Third-party exclusion (initial):  No third-party secret is in scope; the method will not
  access another person's data as a side effect.  ____ (initials)
Signature:                 __________________________
```

## B. Target(s) in scope — one block PER wallet/container (per-target re-verification)

```
Target #:                  ____
Container type:            [ ] phone/tablet  [ ] disk/laptop  [ ] iOS backup  [ ] wallet.dat
                           [ ] keystore JSON [ ] LevelDB/app vault  [ ] paper/partial mnemonic  [ ] other: ____
Container identifier:      __________________________  (serial / filename / volume label)
Container hash (if imaged): _________________________  (e.g., SHA-256 of the image; NO secrets)
Wallet/app + version:      __________________________
Asset(s) expected:         __________________________  (chain, approx amount, known address if any)
Known/target address(es):  __________________________  (PUBLIC only — used for verify-by-derivation)
Derivation standard(s) to try: _____________________   (e.g., BIP-44/49/84/86; coin type)
Ownership evidence (tier): [ ] A  [ ] B  [ ] C(flag)  [ ] D(refuse)
  Evidence items:          __________________________  (remembered spend / exchange record / receipts / sole possession)
Decision:                  [ ] PROCEED  [ ] FLAG & PAUSE (escalated to: ____)  [ ] REFUSE (reason: ____)
```

Repeat block B for each container. A container that appears mid-project gets its own block *before* it is touched — the project-level authorization does not extend to it automatically.

## C. Offline-handling attestation (clear before any secret exists in memory)

```
Machine description:       __________________________
[ ] Radios off/absent (Ethernet unplugged; Wi-Fi/BT/cellular/NFC disabled)
[ ] No cloud sync (clipboard, screenshots/photos, notes/keychain, find-my, settings/browser)
[ ] Telemetry / crash reporting / update phone-home disabled
[ ] swap off (or encrypted swap only); hibernation disabled; ulimit -c 0; crash collector off
[ ] tmpfs for transient secrets; no secrets to internal disk; no secrets in argv/env/history
[ ] Toolchain versions pinned & hashes verified; known-answer test vectors PASS on this machine
Toolchain versions/hashes: __________________________
Attested by:               __________________________  Date/time: ____________
```

(Full checklist and rationale: `offline-key-handling.md` §8.)

## D. Provenance / activity log (append-only; no secrets)

```
Timestamp | Action                                   | Target# | Input hash | Output (public) | Notes
----------+------------------------------------------+---------+-----------+-----------------+------
          | e.g., imaged device                      |         |           | image SHA-256   |
          | e.g., ran KAT vectors (BIP-39/32)        |         |           | PASS/FAIL       |
          | e.g., decrypted keystore header          |         |           | KDF params      |
          | e.g., derived address under m/84'/0'/0'  |         |           | bc1...          |
          | e.g., verify-by-derivation match         |         |           | MATCH/MISMATCH  |
          | e.g., migrated funds to fresh wallet     |         |           | txid            |
          | e.g., secure-erase working plaintext     |         |           | method          |
```

Record *what you did and what you derived*, hashing inputs so the record is tamper-evident (`digital-forensics-fundamentals`). Never record a secret. The log doubles as operational memory so a paused search resumes without re-deriving.

## E. Post-recovery disposition

```
[ ] Recovered secret backed up redundantly OFFLINE (>=2 media, verified readable)  before anything else
[ ] Verified by offline derivation to known address (path: ________)  [ ] MATCH
[ ] Migrated to FRESH wallet (new seed generated clean, backed up)   txid: ________
[ ] Settlement confirmed (confirmations/finality)
[ ] Working plaintext securely erased (method: ________, per NIST SP 800-88)
[ ] Only NEW-wallet offline backups + this (secret-free) record retained
```

---

## Refusal note (use when a target is out of scope)

If any target lands in tier D, do not derive/carve/brute-force it. Record:

```
Refused target #:          ____
Reason:                    [ ] third-party asset  [ ] contested/second claimant
                           [ ] found/secondhand w/ coins  [ ] exfiltration required  [ ] other: ____
Response given:            __________________________  (see scope-and-refusal-rules.md §10 templates)
```

---

Cross-references: `ownership-and-authorization.md` (what the evidence tiers mean), `scope-and-refusal-rules.md` (refuse/flag/proceed), `offline-key-handling.md` (§C checklist), `post-recovery-migration.md` (§E disposition). The imaging/hashing discipline behind the provenance log is in the `digital-forensics-fundamentals` skill.
