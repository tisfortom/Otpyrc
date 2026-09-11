#!/usr/bin/env python3
# mnemonic_to_seed.py
#
# Purpose
#   BIP-39 primitives for the recovery pipeline:
#     * verify a mnemonic's checksum (needs the wordlist for the language used)
#     * turn any mnemonic + optional passphrase (the "25th word") into the
#       64-byte BIP-39 seed via PBKDF2-HMAC-SHA512 (2048 iterations)
#     * recover the raw entropy from a valid English mnemonic
#
#   ONLY use this on the OWNER'S OWN mnemonics, for recovering the OWNER'S OWN
#   assets, with authorization. See ../SKILL.md "Pitfalls & safety".
#
# Key invariants (BIP-39):
#   ENT in {128,160,192,224,256} -> {12,15,18,21,24} words.
#   checksum bits CS = ENT/32; total bits = ENT+CS; words = (ENT+CS)/11.
#   checksum = first CS bits of SHA-256(entropy).
#   seed = PBKDF2(HMAC-SHA512, password=NFKD(mnemonic),
#                 salt="mnemonic"+NFKD(passphrase), c=2048, dkLen=64).
#   NOTE: the seed derivation does NOT touch the wordlist and does NOT verify
#   the checksum. A wrong word still yields a (wrong) seed silently.
#
# Usage:
#   python3 mnemonic_to_seed.py "<mnemonic>" [--passphrase P] [--wordlist FILE]
#   python3 mnemonic_to_seed.py --selftest
#   python3 mnemonic_to_seed.py            # runs --selftest
#
# No network access is used or required.

import hashlib
import sys
import unicodedata

PBKDF2_ITERS = 2048
SEED_LEN = 64


def _nfkd(s: str) -> str:
    return unicodedata.normalize("NFKD", s)


def normalize_mnemonic(mnemonic: str) -> str:
    # BIP-39: words are separated by a single ASCII space after NFKD.
    return " ".join(_nfkd(mnemonic).split())


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """BIP-39 mnemonic + optional passphrase -> 64-byte seed. No checksum check."""
    m = _nfkd(mnemonic)
    m = " ".join(m.split())  # collapse whitespace, keep exact words
    salt = _nfkd("mnemonic" + passphrase)
    return hashlib.pbkdf2_hmac(
        "sha512", m.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ITERS, dklen=SEED_LEN
    )


def load_wordlist(path: str):
    with open(path, "r", encoding="utf-8") as f:
        words = [_nfkd(w.strip()) for w in f if w.strip()]
    if len(words) != 2048:
        raise ValueError(f"wordlist must have 2048 entries, got {len(words)}")
    return words


def _bits_to_bytes(bits: str) -> bytes:
    return int(bits, 2).to_bytes(len(bits) // 8, "big")


def verify_checksum(mnemonic: str, wordlist):
    """Return (ok, entropy_bytes). Raises on structural errors."""
    index = {w: i for i, w in enumerate(wordlist)}
    words = normalize_mnemonic(mnemonic).split()
    if len(words) not in (12, 15, 18, 21, 24):
        raise ValueError(f"word count {len(words)} is not a valid BIP-39 length")
    bad = [w for w in words if w not in index]
    if bad:
        raise ValueError(f"words not in wordlist: {bad}")
    bitstr = "".join(format(index[w], "011b") for w in words)
    total = len(bitstr)               # ENT + CS
    ent = total * 32 // 33            # ENT is 32/33 of the total
    cs = total - ent
    ent_bits, cs_bits = bitstr[:ent], bitstr[ent:]
    entropy = _bits_to_bytes(ent_bits)
    h = hashlib.sha256(entropy).digest()
    expected = "".join(format(b, "08b") for b in h)[:cs]
    return (expected == cs_bits), entropy


def _selftest() -> int:
    # Canonical Trezor BIP-39 vector: 128 bits of zero entropy.
    m = "abandon abandon abandon abandon abandon abandon abandon " \
        "abandon abandon abandon abandon about"
    seed = mnemonic_to_seed(m, "TREZOR").hex()
    expect = ("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708"
              "e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b"
              "2f001698e7463b04")
    assert seed == expect, f"seed mismatch:\n {seed}\n {expect}"
    # Empty passphrase differs from the "TREZOR" one (passphrase is salted in).
    assert mnemonic_to_seed(m).hex() != expect
    # A single changed word yields a totally different seed (no checksum guard).
    bad = m.replace("about", "abandon")
    assert mnemonic_to_seed(bad, "TREZOR").hex() != expect
    print("selftest OK: BIP-39 seed derivation matches the Trezor vector")
    return 0


def main(argv):
    if not argv or argv[0] in ("--selftest", "-t"):
        return _selftest()
    if argv[0] in ("-h", "--help"):
        print("usage: mnemonic_to_seed.py \"<mnemonic>\" "
              "[--passphrase P] [--wordlist FILE]")
        return 0
    mnemonic = argv[0]
    passphrase = ""
    wl = None
    i = 1
    while i < len(argv):
        if argv[i] == "--passphrase":
            passphrase = argv[i + 1]; i += 2
        elif argv[i] == "--wordlist":
            wl = argv[i + 1]; i += 2
        else:
            print(f"unknown arg: {argv[i]}", file=sys.stderr); return 2
    if wl:
        ok, entropy = verify_checksum(mnemonic, load_wordlist(wl))
        print(f"checksum: {'VALID' if ok else 'INVALID'}")
        print(f"entropy:  {entropy.hex()} ({len(entropy)*8} bits)")
        if not ok:
            print("WARNING: checksum invalid; seed below is derived anyway "
                  "(BIP-39 seed derivation never checks the checksum).")
    seed = mnemonic_to_seed(mnemonic, passphrase)
    print(f"seed:     {seed.hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
