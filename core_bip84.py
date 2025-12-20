# core_bip84.py
# -*- coding: utf-8 -*-

import json
import hashlib
from dataclasses import dataclass
from typing import List, Tuple

from embit import bip39, bip32, script
from embit.networks import NETWORKS


# =========================================================
# Base58Check (para converter xpub -> zpub)
# =========================================================
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = []
    while n > 0:
        n, r = divmod(n, 58)
        out.append(_B58_ALPHABET[r])

    # leading zeros -> leading "1"
    pad = 0
    for c in b:
        if c == 0:
            pad += 1
        else:
            break

    if not out:
        return "1" * pad if pad else ""
    return "1" * pad + "".join(reversed(out))


def _b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        idx = _B58_ALPHABET.find(ch)
        if idx < 0:
            raise ValueError("Base58 inválido")
        n = n * 58 + idx

    b = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""

    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + b


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
# xpub version: 0488B21E
# zpub version: 04B24746
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
# Result container
# =========================================================
@dataclass
class WalletResult:
    entropy_hex: str
    mnemonic_24: str
    master_fingerprint_hex: str
    derivation: str
    xpub: str
    zpub: str
    external_addrs: List[Tuple[str, str]]  # (path, addr)
    change_addrs: List[Tuple[str, str]]    # (path, addr)
    desc_external: str
    desc_change: str


# =========================================================
# Entropy: SHA512(text+pass) -> reverse -> SHA256
# =========================================================
def _entropy_sha512rev_sha256(text: str, passphrase: str) -> bytes:
    # separador evita ambiguidade de concatenação
    data = (text + "\n---\n" + passphrase).encode("utf-8")
    h512 = hashlib.sha512(data).digest()
    return hashlib.sha256(h512[::-1]).digest()  # 32 bytes (256-bit)


# =========================================================
# Main derivation (BIP84)
# =========================================================
def derive_bip84_from_text(
    fonte_text: str,
    bip39_passphrase: str,
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

    # embit usa "h" pra hardened
    derivation_core = f"m/84h/{coin}h/{account}h"
    derivation_display = derivation_core.replace("h", "'")

    # 1) entropy (256-bit)
    entropy = _entropy_sha512rev_sha256(fonte_text, bip39_passphrase)

    # 2) mnemonic (24 palavras)
    mnemonic = bip39.mnemonic_from_bytes(entropy)

    # 3) seed (BIP39 PBKDF2) - aqui é o FIX: sem keyword passphrase=
    seed = bip39.mnemonic_to_seed(mnemonic, bip39_passphrase)

    # 4) root + fingerprint
    root = bip32.HDKey.from_seed(seed)
    mfp = root.fingerprint.hex()

    # 5) account xpub
    acct_xprv = root.derive(derivation_core)
    acct_xpub_key = acct_xprv.to_public()

    xpub = acct_xpub_key.to_base58()
    # zpub só faz sentido no mainnet; no testnet o "certo" seria vpub.
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

    # 7) descriptors (sem checksum)
    # Ex: wpkh([FPR/84'/0'/0']xpub/0/*)
    origin = f"[{mfp}/{derivation_display[2:]}]"  # remove "m/"
    desc_ext = f"wpkh({origin}{xpub}/0/*)"
    desc_chg = f"wpkh({origin}{xpub}/1/*)"

    return WalletResult(
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
