#!/usr/bin/env python3
# bip32_derive.py
#
# Purpose
#   Pure-stdlib BIP-32 hierarchical deterministic key derivation over
#   secp256k1: master key from a seed, CKDpriv / CKDpub, extended-key
#   (xprv/xpub, tprv/tpub) serialization + Base58Check, and BIP-32 path
#   parsing ("m/44'/0'/0'/0/0"). Also importable as a module by the other
#   scripts in this directory.
#
#   Use ONLY on the OWNER'S OWN seed to recover the OWNER'S OWN wallet, with
#   authorization. Treat every printed xprv as a live secret.
#
# Key invariants (BIP-32):
#   master:  I = HMAC-SHA512(key="Bitcoin seed", data=seed)
#            IL = master private key (must be 0 < IL < n), IR = chain code.
#   hardened child (i >= 2^31):
#            I = HMAC-SHA512(cpar, 0x00 || ser256(kpar) || ser32(i))
#   normal child (i <  2^31):
#            I = HMAC-SHA512(cpar, serP(point(kpar)) || ser32(i))
#   ki = (IL + kpar) mod n ; ci = IR.  If IL >= n or ki == 0 -> skip index.
#   CKDpub works for NORMAL indices only; hardened public derivation is
#   mathematically impossible (that is the point of the ' hardening).
#   fingerprint = first 4 bytes of RIPEMD160(SHA256(compressed_pubkey)).
#
# Usage:
#   python3 bip32_derive.py <seed_hex> <path> [--testnet] [--pub]
#   python3 bip32_derive.py --selftest      (also runs with no args)
#
# Example:
#   python3 bip32_derive.py 000102...0f "m/0'/1" --pub
#
# No network access is used or required.

import hashlib
import hmac
import sys

# ---- secp256k1 domain parameters (SEC 2) ----------------------------------
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A  = 0
B  = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G  = (Gx, Gy)

HARDENED = 0x80000000

# Extended-key version bytes (BIP-32).
VER = {
    ("main", "priv"): 0x0488ADE4,   # xprv
    ("main", "pub"):  0x0488B21E,   # xpub
    ("test", "priv"): 0x04358394,   # tprv
    ("test", "pub"):  0x043587CF,   # tpub
}


def inv(x, m):
    return pow(x, -1, m)


def ec_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % P == 0:
        return None  # point at infinity
    if p == q:
        s = (3 * x1 * x1 + A) * inv(2 * y1, P) % P
    else:
        s = (y2 - y1) * inv(x2 - x1, P) % P
    x3 = (s * s - x1 - x2) % P
    y3 = (s * (x1 - x3) - y1) % P
    return (x3, y3)


def ec_mul(k, p=G):
    r = None
    while k:
        if k & 1:
            r = ec_add(r, p)
        p = ec_add(p, p)
        k >>= 1
    return r


def ser32(i):
    return i.to_bytes(4, "big")


def ser256(x):
    return x.to_bytes(32, "big")


def ser_p(point):
    """SEC1 compressed encoding of an EC point (33 bytes)."""
    x, y = point
    return bytes([2 + (y & 1)]) + ser256(x)


def pubkey(k_priv):
    return ser_p(ec_mul(k_priv))


# ---- RIPEMD-160 (pure Python; hashlib often lacks it) ---------------------
def _ripemd160(msg: bytes) -> bytes:
    try:
        return hashlib.new("ripemd160", msg).digest()
    except Exception:
        pass
    rol = lambda x, n: ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    rl = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
          7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
          3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
          1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
          4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13]
    rr = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
          6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
          15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
          8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
          12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11]
    sl = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
          7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
          11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
          11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
          9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6]
    sr = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
          9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
          9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
          15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
          8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]
    kl = [0x00000000,0x5A827999,0x6ED9EBA1,0x8F1BBCDC,0xA953FD4E]
    kr = [0x50A28BE6,0x5C4DD124,0x6D703EF3,0x7A6D76E9,0x00000000]

    def f(j, x, y, z):
        if j < 16: return x ^ y ^ z
        if j < 32: return (x & y) | (~x & z)
        if j < 48: return (x | ~y) ^ z
        if j < 64: return (x & z) | (y & ~z)
        return x ^ (y | ~z)

    ml = len(msg)
    msg = msg + b"\x80"
    while len(msg) % 64 != 56:
        msg += b"\x00"
    msg += (ml * 8 & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
    h0, h1, h2, h3, h4 = (0x67452301, 0xEFCDAB89, 0x98BADCFE,
                          0x10325476, 0xC3D2E1F0)
    for off in range(0, len(msg), 64):
        X = [int.from_bytes(msg[off + 4 * i:off + 4 * i + 4], "little")
             for i in range(16)]
        al, bl, cl, dl, el = h0, h1, h2, h3, h4
        ar, br, cr, dr, er = h0, h1, h2, h3, h4
        for j in range(80):
            t = (al + f(j, bl, cl, dl) + X[rl[j]] + kl[j // 16]) & 0xFFFFFFFF
            t = (rol(t, sl[j]) + el) & 0xFFFFFFFF
            al, el, dl, cl, bl = el, dl, rol(cl, 10), bl, t
            t = (ar + f(79 - j, br, cr, dr) + X[rr[j]] + kr[j // 16]) & 0xFFFFFFFF
            t = (rol(t, sr[j]) + er) & 0xFFFFFFFF
            ar, er, dr, cr, br = er, dr, rol(cr, 10), br, t
        t  = (h1 + cl + dr) & 0xFFFFFFFF
        h1 = (h2 + dl + er) & 0xFFFFFFFF
        h2 = (h3 + el + ar) & 0xFFFFFFFF
        h3 = (h4 + al + br) & 0xFFFFFFFF
        h4 = (h0 + bl + cr) & 0xFFFFFFFF
        h0 = t
    return b"".join(h.to_bytes(4, "little") for h in (h0, h1, h2, h3, h4))


def hash160(b: bytes) -> bytes:
    return _ripemd160(hashlib.sha256(b).digest())


# ---- Base58Check -----------------------------------------------------------
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check_encode(payload: bytes) -> str:
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    data = payload + chk
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    out = "1" * (len(data) - len(data.lstrip(b"\x00"))) + out
    return out


def b58check_decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + _B58.index(ch)
    full = n.to_bytes((n.bit_length() + 7) // 8, "big")
    full = b"\x00" * (len(s) - len(s.lstrip("1"))) + full
    payload, chk = full[:-4], full[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != chk:
        raise ValueError("bad Base58Check checksum")
    return payload


# ---- Extended keys ---------------------------------------------------------
class XKey:
    __slots__ = ("net", "priv", "depth", "parent_fp", "child", "chain", "key")

    def __init__(self, net, priv, depth, parent_fp, child, chain, key):
        self.net = net          # "main" | "test"
        self.priv = priv        # bool
        self.depth = depth
        self.parent_fp = parent_fp   # 4 bytes
        self.child = child      # int
        self.chain = chain      # 32 bytes
        self.key = key          # int (priv) or 33-byte compressed pub

    def pub_bytes(self):
        return pubkey(self.key) if self.priv else self.key

    def fingerprint(self):
        return hash160(self.pub_bytes())[:4]

    def serialize(self, as_pub=False):
        want_pub = as_pub or not self.priv
        ver = VER[(self.net, "pub" if want_pub else "priv")]
        keydata = self.pub_bytes() if want_pub else (b"\x00" + ser256(self.key))
        raw = (ver.to_bytes(4, "big") + bytes([self.depth]) + self.parent_fp +
               ser32(self.child) + self.chain + keydata)
        return b58check_encode(raw)


def master_from_seed(seed: bytes, net="main") -> XKey:
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    il, ir = int.from_bytes(I[:32], "big"), I[32:]
    if il == 0 or il >= N:
        raise ValueError("invalid seed: master key not in [1, n-1]")
    return XKey(net, True, 0, b"\x00\x00\x00\x00", 0, ir, il)


def ckd_priv(par: XKey, i: int) -> XKey:
    if not par.priv:
        raise ValueError("CKDpriv needs a private parent")
    if i >= HARDENED:
        data = b"\x00" + ser256(par.key) + ser32(i)
    else:
        data = par.pub_bytes() + ser32(i)
    I = hmac.new(par.chain, data, hashlib.sha512).digest()
    il = int.from_bytes(I[:32], "big")
    ki = (il + par.key) % N
    if il >= N or ki == 0:
        raise ValueError(f"index {i} invalid (prob ~2^-127); use next index")
    return XKey(par.net, True, par.depth + 1, par.fingerprint(), i, I[32:], ki)


def ckd_pub(par: XKey, i: int) -> XKey:
    if i >= HARDENED:
        raise ValueError("cannot derive a hardened child from a public key")
    Kpar = par.pub_bytes()
    data = Kpar + ser32(i)
    I = hmac.new(par.chain, data, hashlib.sha512).digest()
    il = int.from_bytes(I[:32], "big")
    if il >= N:
        raise ValueError(f"index {i} invalid; use next index")
    point = ec_add(ec_mul(il), _decompress(Kpar))
    if point is None:
        raise ValueError(f"index {i} invalid (point at infinity)")
    return XKey(par.net, False, par.depth + 1, par.fingerprint(), i,
                I[32:], ser_p(point))


def _decompress(comp: bytes):
    prefix, x = comp[0], int.from_bytes(comp[1:], "big")
    y2 = (pow(x, 3, P) + B) % P
    y = pow(y2, (P + 1) // 4, P)
    if (y & 1) != (prefix & 1):
        y = P - y
    return (x, y)


def parse_path(path: str):
    path = path.strip()
    if path in ("m", "M", ""):
        return []
    parts = path.split("/")
    if parts[0] in ("m", "M"):
        parts = parts[1:]
    out = []
    for p in parts:
        hard = p.endswith("'") or p.endswith("h") or p.endswith("H")
        n = int(p.rstrip("'hH"))
        out.append(n + HARDENED if hard else n)
    return out


def derive_path(master: XKey, path: str) -> XKey:
    node = master
    for i in parse_path(path):
        node = ckd_priv(node, i)
    return node


# ---- self-test -------------------------------------------------------------
def _selftest() -> int:
    # RIPEMD-160 known-answer vectors.
    assert _ripemd160(b"").hex() == "9c1185a5c5e9fc54612808977ee8f548b2258d31"
    assert _ripemd160(b"abc").hex() == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"

    # BIP-32 official Test Vector 1 (seed 000102...0f).
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    m = master_from_seed(seed)
    assert m.serialize() == (
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNK"
        "mPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
    assert m.serialize(as_pub=True) == (
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFj"
        "qJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
    n0h = derive_path(m, "m/0'")
    assert n0h.serialize() == (
        "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5h"
        "j6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7")
    # CKDpub on a NORMAL child must match CKDpriv-then-serialize-pub.
    n01 = derive_path(m, "m/0'/1")
    n0h_pub = ckd_pub(n0h, 1)
    assert n0h_pub.serialize() == n01.serialize(as_pub=True), "CKDpub mismatch"
    # Hardened public derivation must be refused.
    try:
        ckd_pub(n0h, HARDENED)
        raise AssertionError("hardened CKDpub should have failed")
    except ValueError:
        pass
    print("selftest OK: RIPEMD-160 + BIP-32 vector 1 + CKDpub consistency")
    return 0


def main(argv):
    if not argv or argv[0] in ("--selftest", "-t"):
        return _selftest()
    if argv[0] in ("-h", "--help"):
        print("usage: bip32_derive.py <seed_hex> <path> [--testnet] [--pub]")
        return 0
    seed = bytes.fromhex(argv[0])
    path = argv[1] if len(argv) > 1 else "m"
    net = "test" if "--testnet" in argv else "main"
    as_pub = "--pub" in argv
    node = derive_path(master_from_seed(seed, net), path)
    print(f"path:        {path}")
    print(f"depth:       {node.depth}  child: {node.child}")
    print(f"chain code:  {node.chain.hex()}")
    print(f"public key:  {node.pub_bytes().hex()}")
    print(f"hash160:     {hash160(node.pub_bytes()).hex()}")
    print(f"xpub:        {node.serialize(as_pub=True)}")
    if not as_pub:
        print(f"xprv:        {node.serialize()}   [SECRET]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
