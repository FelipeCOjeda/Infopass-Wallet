# core_bip84.py
# -*- coding: utf-8 -*-

"""
InfoPass-Wallet – BIP84 deterministic wallet generator.

Derives a BIP84 (Native SegWit / P2WPKH) wallet from arbitrary text + passphrase.
Supports three entropy-derivation methods (KDFs):
  - legacy   : SHA512 → reverse → SHA256  (original, kept for backward compat)
  - hkdf     : HKDF-SHA256 (RFC 5869)
  - argon2id : Argon2id (RFC 9106) – recommended for brute-force resistance
"""

import json
import hashlib
import hmac
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import List, Tuple

from embit import bip39, bip32, script
from embit.networks import NETWORKS

try:
    from argon2.low_level import hash_secret_raw, Type
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False


# =========================================================
# KDF enum
# =========================================================
class KDF(str, Enum):
    LEGACY = "legacy"
    HKDF = "hkdf"
    ARGON2ID = "argon2id"


# =========================================================
# Base58Check (xpub → zpub conversion)
# =========================================================
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out: list[str] = []
    while n > 0:
        n, r = divmod(n, 58)
        out.append(_B58_ALPHABET[r])

    pad = 0
    for byte in b:
        if byte == 0:
            pad += 1
        else:
            break

    if not out:
        return "1" * max(pad, 1)
    return "1" * pad + "".join(reversed(out))


def _b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        idx = _B58_ALPHABET.find(ch)
        if idx < 0:
            raise ValueError(f"Caractere Base58 inválido: {ch!r}")
        n = n * 58 + idx

    byte_len = max((n.bit_length() + 7) // 8, 1) if n else 1
    b = n.to_bytes(byte_len, "big") if n else b"\x00"

    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + (b if n else b"")


def _hash256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def b58check_encode(payload: bytes) -> str:
    return _b58encode(payload + _hash256(payload)[:4])


def b58check_decode(s: str) -> bytes:
    raw = _b58decode(s)
    if len(raw) < 5:
        raise ValueError("Base58Check curto demais")
    payload, chk = raw[:-4], raw[-4:]
    if _hash256(payload)[:4] != chk:
        raise ValueError("Checksum inválido (Base58Check)")
    return payload


# SLIP-132 / BIP84 (mainnet)
XPUB_VER = bytes.fromhex("0488B21E")
ZPUB_VER = bytes.fromhex("04B24746")


def xpub_to_zpub(xpub: str) -> str:
    payload = b58check_decode(xpub)
    if len(payload) != 78:
        raise ValueError("XPUB payload inesperado")
    if payload[:4] != XPUB_VER:
        raise ValueError("Não parece um xpub mainnet")
    return b58check_encode(ZPUB_VER + payload[4:])


# =========================================================
# Unicode normalization helper
# =========================================================
def _normalize(text: str) -> str:
    """NFC-normalize to ensure consistent entropy across platforms."""
    return unicodedata.normalize("NFC", text)


# =========================================================
# Entropy derivation – three methods
# =========================================================
_HKDF_SALT = b"infopass-wallet-v1"
_HKDF_INFO = b"bip84-entropy-256"
_ARGON2_SALT = b"infopass-wallet-v1"


def _combine_inputs(text: str, passphrase: str) -> bytes:
    """Normalize and combine text + passphrase with an unambiguous separator."""
    return (_normalize(text) + "\n---\n" + _normalize(passphrase)).encode("utf-8")


def _entropy_legacy(text: str, passphrase: str) -> bytes:
    """Original scheme: SHA512 → reverse bytes → SHA256. 256-bit output."""
    data = _combine_inputs(text, passphrase)
    h512 = hashlib.sha512(data).digest()
    return hashlib.sha256(h512[::-1]).digest()


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 (RFC 5869) – extract-then-expand."""
    # Extract
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    # Expand (length ≤ 32 → single block)
    t = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return t[:length]


def _entropy_hkdf(text: str, passphrase: str) -> bytes:
    """HKDF-SHA256 entropy derivation. 256-bit output."""
    ikm = _combine_inputs(text, passphrase)
    return _hkdf_sha256(ikm, _HKDF_SALT, _HKDF_INFO, 32)


def _entropy_argon2id(text: str, passphrase: str) -> bytes:
    """Argon2id entropy derivation. 256-bit output. Brute-force resistant."""
    if not ARGON2_AVAILABLE:
        raise RuntimeError(
            "argon2-cffi não está instalado.\n"
            "Instale com: pip install argon2-cffi"
        )
    secret = _combine_inputs(text, passphrase)
    return hash_secret_raw(
        secret=secret,
        salt=_ARGON2_SALT,
        time_cost=3,
        memory_cost=65536,       # 64 MiB
        parallelism=4,
        hash_len=32,
        type=Type.ID,
    )


_KDF_FUNCS = {
    KDF.LEGACY: _entropy_legacy,
    KDF.HKDF: _entropy_hkdf,
    KDF.ARGON2ID: _entropy_argon2id,
}


def derive_entropy(text: str, passphrase: str, kdf: KDF = KDF.HKDF) -> bytes:
    """Derive 256-bit entropy using the chosen KDF."""
    return _KDF_FUNCS[kdf](text, passphrase)


# =========================================================
# Result container
# =========================================================
@dataclass
class WalletResult:
    kdf_used: str
    entropy_hex: str
    mnemonic_24: str
    master_fingerprint_hex: str
    derivation: str
    xpub: str
    zpub: str
    external_addrs: List[Tuple[str, str]]
    change_addrs: List[Tuple[str, str]]
    desc_external: str
    desc_change: str


# =========================================================
# Main derivation (BIP84)
# =========================================================
def derive_bip84_from_text(
    fonte_text: str,
    bip39_passphrase: str,
    kdf: KDF = KDF.HKDF,
    network: str = "main",
    account: int = 0,
    external_count: int = 10,
    change_count: int = 10,
) -> WalletResult:
    if not fonte_text or not fonte_text.strip():
        raise ValueError("Fonte (texto) está vazia.")

    if network not in ("main", "test"):
        raise ValueError("network inválida. Use 'main' ou 'test'.")

    net = NETWORKS["main"] if network == "main" else NETWORKS["test"]
    coin = 0 if network == "main" else 1

    derivation_core = f"m/84h/{coin}h/{account}h"
    derivation_display = derivation_core.replace("h", "'")

    # 1) entropy (256-bit) via chosen KDF
    entropy = derive_entropy(fonte_text, bip39_passphrase, kdf)

    # 2) mnemonic (24 words)
    mnemonic = bip39.mnemonic_from_bytes(entropy)

    # 3) seed (BIP39 PBKDF2)
    seed = bip39.mnemonic_to_seed(mnemonic, bip39_passphrase)

    # 4) root + fingerprint
    root = bip32.HDKey.from_seed(seed)
    mfp = root.fingerprint.hex()

    # 5) account xpub
    acct_xprv = root.derive(derivation_core)
    acct_xpub_key = acct_xprv.to_public()

    xpub = acct_xpub_key.to_base58()
    zpub = xpub_to_zpub(xpub) if network == "main" else xpub

    # 6) addresses
    external = []
    for i in range(max(0, int(external_count))):
        pub = acct_xpub_key.derive([0, i]).key
        addr = script.p2wpkh(pub).address(net)
        external.append((f"{derivation_display}/0/{i}", addr))

    change = []
    for i in range(max(0, int(change_count))):
        pub = acct_xpub_key.derive([1, i]).key
        addr = script.p2wpkh(pub).address(net)
        change.append((f"{derivation_display}/1/{i}", addr))

    # 7) descriptors (without checksum)
    origin = f"[{mfp}/{derivation_display[2:]}]"
    desc_ext = f"wpkh({origin}{xpub}/0/*)"
    desc_chg = f"wpkh({origin}{xpub}/1/*)"

    return WalletResult(
        kdf_used=kdf.value,
        entropy_hex=entropy.hex(),
        mnemonic_24=mnemonic,
        master_fingerprint_hex=mfp,
        derivation=derivation_display,
        xpub=xpub,
        zpub=zpub,
        external_addrs=external,
        change_addrs=change,
        desc_external=desc_ext,
        desc_change=desc_chg,
    )


# =========================================================
# Exports
# =========================================================
def export_descriptors_txt(path: str, r: WalletResult) -> None:
    content = (
        "# Output Descriptors (BIP84 / P2WPKH)\n"
        f"# kdf: {r.kdf_used}\n"
        f"# mfp: {r.master_fingerprint_hex}\n"
        f"# derivation: {r.derivation}\n\n"
        f"{r.desc_external}\n"
        f"{r.desc_change}\n"
    )
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)


def export_sparrow_like_json(path: str, r: WalletResult) -> None:
    obj = {
        "format": "infopass-bip84",
        "kdf": r.kdf_used,
        "network": "mainnet" if r.zpub != r.xpub else "testnet_or_unknown",
        "master_fingerprint": r.master_fingerprint_hex.upper(),
        "derivation": r.derivation,
        "xpub": r.xpub,
        "zpub": r.zpub,
        "descriptors": {
            "external": r.desc_external,
            "change": r.desc_change,
        },
        "first_addresses": {
            "external_0": r.external_addrs[0][1] if r.external_addrs else None,
            "external_1": r.external_addrs[1][1] if len(r.external_addrs) > 1 else None,
            "change_0": r.change_addrs[0][1] if r.change_addrs else None,
        },
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
