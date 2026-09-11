#!/usr/bin/env python3
# derivation_path_sweeper.py
#
# Purpose
#   Given the OWNER'S OWN mnemonic (or raw seed) + optional passphrase, sweep
#   the standard derivation-path templates used by real wallets and print the
#   first N addresses of each, in every relevant address encoding. This is the
#   "which standard did their wallet use?" triage step: run it, then match the
#   printed addresses against ones the owner remembers or that appear on-chain.
#
#   Templates covered:
#     BIP-44  m/44'/c'/a'/chg/i    legacy P2PKH (base58, "1...") / ETH
#     BIP-49  m/49'/c'/a'/chg/i    P2SH-P2WPKH  (base58, "3...")
#     BIP-84  m/84'/c'/a'/chg/i    native segwit P2WPKH (bech32,  "bc1q...")
#     BIP-86  m/86'/c'/a'/chg/i    taproot P2TR         (bech32m, "bc1p...")
#     Ledger-Live ETH, MetaMask/Trust ETH (both m/44'/60'/0'/0/i), plus the
#     legacy per-account ETH quirk m/44'/60'/i'/0/0.
#   coin types are SLIP-0044 (BTC=0, ETH=60, testnet=1).
#
#   Uses bip32_derive.py + mnemonic_to_seed.py from this same directory.
#   Pure stdlib, no network. Owner-only, authorized self-recovery.
#
# Usage:
#   python3 derivation_path_sweeper.py --mnemonic "<words>" [--passphrase P]
#                                      [--count 5] [--coin btc|eth|all]
#   python3 derivation_path_sweeper.py --seed <hex> [--count 5]
#   python3 derivation_path_sweeper.py --selftest        (also: no args)

import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bip32_derive as b32
from bip32_derive import (P, B, ec_mul, ec_add, ser256, hash160,
                          master_from_seed, derive_path, b58check_encode)
from mnemonic_to_seed import mnemonic_to_seed


# ---- bech32 / bech32m (BIP-173 / BIP-350) ---------------------------------
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32M_CONST = 0x2bc830a3


def _polymod(values):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data, frm, to, pad=True):
    acc = 0
    bits = 0
    out = []
    maxv = (1 << to) - 1
    for value in data:
        acc = (acc << frm) | value
        bits += frm
        while bits >= to:
            bits -= to
            out.append((acc >> bits) & maxv)
    if pad and bits:
        out.append((acc << (to - bits)) & maxv)
    return out


def segwit_encode(hrp, witver, witprog):
    const = _BECH32M_CONST if witver else 1
    data = [witver] + _convertbits(list(witprog), 8, 5)
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[d] for d in data + checksum)


# ---- keccak-256 (Ethereum; 0x01 padding, NOT SHA3's 0x06) -----------------
_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_KECCAK_ROT = [
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_MASK = (1 << 64) - 1


def _rotl(x, n):
    return ((x << n) | (x >> (64 - n))) & _MASK


def _keccak_f(a):
    for rnd in range(24):
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]
        bb = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                bb[y][(2 * x + 3 * y) % 5] = _rotl(a[x][y], _KECCAK_ROT[x][y])
        for x in range(5):
            for y in range(5):
                a[x][y] = bb[x][y] ^ ((~bb[(x + 1) % 5][y]) & bb[(x + 2) % 5][y])
        a[0][0] ^= _KECCAK_RC[rnd]
    return a


def keccak256(msg: bytes) -> bytes:
    rate = 136  # 1088 bits
    a = [[0] * 5 for _ in range(5)]
    padded = bytearray(msg) + b"\x01"
    while len(padded) % rate != 0:
        padded.append(0)
    padded[-1] ^= 0x80
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[i * 8:i * 8 + 8], "little")
            a[i % 5][i // 5] ^= lane
        a = _keccak_f(a)
    out = bytearray()
    for i in range(4):  # 32 bytes fit in the first 4 lanes of the rate
        out += a[i % 5][i // 5].to_bytes(8, "little")
    return bytes(out[:32])


# ---- address builders ------------------------------------------------------
def p2pkh(pub33, ver=0x00):
    return b58check_encode(bytes([ver]) + hash160(pub33))


def p2sh_p2wpkh(pub33, ver=0x05):
    redeem = b"\x00\x14" + hash160(pub33)
    return b58check_encode(bytes([ver]) + hash160(redeem))


def p2wpkh(pub33, hrp="bc"):
    return segwit_encode(hrp, 0, hash160(pub33))


def _tagged_hash(tag, msg):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def _lift_x(x):
    c = (pow(x, 3, P) + B) % P
    y = pow(c, (P + 1) // 4, P)
    if (y * y - c) % P != 0:
        raise ValueError("x is not on the curve")
    return (x, y if y % 2 == 0 else P - y)  # BIP-340 even-y


def p2tr(pub33, hrp="bc"):
    # BIP-86 single-key taproot: tweak the x-only internal key by
    # t = tagged_hash("TapTweak", x); Q = lift_x(x) + t*G ; output = Q.x.
    x = int.from_bytes(pub33[1:], "big")
    px, py = _lift_x(x)
    t = int.from_bytes(_tagged_hash("TapTweak", ser256(x)), "big")
    q = ec_add((px, py), ec_mul(t))
    return segwit_encode(hrp, 1, ser256(q[0]))


def eth_address(pub33):
    # Ethereum address = last 20 bytes of keccak256(uncompressed pubkey, no 0x04
    # prefix, i.e. the 64-byte X||Y). Returns EIP-55 checksummed hex.
    x = int.from_bytes(pub33[1:], "big")
    px, py = b32._decompress(pub33)
    raw = px.to_bytes(32, "big") + py.to_bytes(32, "big")
    addr = keccak256(raw)[-20:].hex()
    h = keccak256(addr.encode()).hex()
    return "0x" + "".join(c.upper() if int(h[i], 16) >= 8 else c
                          for i, c in enumerate(addr))


# ---- sweep -----------------------------------------------------------------
TEMPLATES = [
    ("BIP-44 BTC P2PKH",     "m/44'/0'/0'/0/{i}", "btc", p2pkh),
    ("BIP-49 BTC P2SH-WPKH", "m/49'/0'/0'/0/{i}", "btc", p2sh_p2wpkh),
    ("BIP-84 BTC P2WPKH",    "m/84'/0'/0'/0/{i}", "btc", p2wpkh),
    ("BIP-86 BTC P2TR",      "m/86'/0'/0'/0/{i}", "btc", p2tr),
    ("MetaMask/Trust ETH",   "m/44'/60'/0'/0/{i}", "eth", eth_address),
    ("Ledger-legacy ETH",    "m/44'/60'/{i}'/0/0", "eth", eth_address),
]


def sweep(master, count, coin):
    for label, tmpl, kind, fn in TEMPLATES:
        if coin != "all" and coin != kind:
            continue
        print(f"\n== {label:22s} {tmpl}")
        for i in range(count):
            node = derive_path(master, tmpl.format(i=i))
            print(f"   {tmpl.format(i=i):24s} {fn(node.pub_bytes())}")


def _selftest() -> int:
    # keccak256 known-answer.
    assert keccak256(b"").hex() == \
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    m = ("abandon abandon abandon abandon abandon abandon abandon "
         "abandon abandon abandon abandon about")
    seed = mnemonic_to_seed(m)
    master = master_from_seed(seed)
    # Canonical BIP-84 receive #0.
    n84 = derive_path(master, "m/84'/0'/0'/0/0")
    assert p2wpkh(n84.pub_bytes()) == \
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", "BIP-84 vector failed"
    # Canonical BIP-86 receive #0 (taproot tweak + bech32m).
    n86 = derive_path(master, "m/86'/0'/0'/0/0")
    assert p2tr(n86.pub_bytes()) == \
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr", \
        "BIP-86 vector failed"
    # BIP-173 native-segwit encoder vector.
    hp = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
    assert b32._decompress  # module wired
    assert segwit_encode("bc", 0, hp) == \
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    # EIP-55 checksum sanity: output is a 0x + 40 hex address.
    eth = eth_address(derive_path(master, "m/44'/60'/0'/0/0").pub_bytes())
    assert eth.startswith("0x") and len(eth) == 42
    print("selftest OK: keccak256 + BIP-84 + BIP-86 + bech32 vectors")
    print(f"  sample ETH m/44'/60'/0'/0/0: {eth}")
    return 0


def main(argv):
    if not argv or argv[0] in ("--selftest", "-t"):
        return _selftest()
    if argv[0] in ("-h", "--help"):
        print("usage: derivation_path_sweeper.py "
              "(--mnemonic \"words\" [--passphrase P] | --seed HEX) "
              "[--count N] [--coin btc|eth|all]")
        return 0
    mnemonic = seed_hex = None
    passphrase = ""
    count = 3
    coin = "all"
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--mnemonic": mnemonic = argv[i + 1]; i += 2
        elif a == "--seed": seed_hex = argv[i + 1]; i += 2
        elif a == "--passphrase": passphrase = argv[i + 1]; i += 2
        elif a == "--count": count = int(argv[i + 1]); i += 2
        elif a == "--coin": coin = argv[i + 1]; i += 2
        else:
            print(f"unknown arg: {a}", file=sys.stderr); return 2
    if seed_hex:
        seed = bytes.fromhex(seed_hex)
    elif mnemonic:
        seed = mnemonic_to_seed(mnemonic, passphrase)
    else:
        print("need --mnemonic or --seed", file=sys.stderr); return 2
    print("WARNING: derived xprv/keys are live secrets; run offline only.")
    sweep(master_from_seed(seed), count, coin)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
