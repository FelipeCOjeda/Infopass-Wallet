# test_core.py
# -*- coding: utf-8 -*-

"""Unit tests for core_bip84."""

import json
import os
import tempfile

import pytest

from core_bip84 import (
    KDF,
    WalletResult,
    b58check_decode,
    b58check_encode,
    derive_bip84_from_text,
    derive_entropy,
    export_descriptors_txt,
    export_sparrow_like_json,
    xpub_to_zpub,
    _normalize,
)


# =========================================================
# Fixtures
# =========================================================
SAMPLE_TEXT = "The quick brown fox jumps over the lazy dog"
SAMPLE_PASS = "s3cretP@ssphr4se!"


@pytest.fixture
def wallet_hkdf() -> WalletResult:
    return derive_bip84_from_text(SAMPLE_TEXT, SAMPLE_PASS, kdf=KDF.HKDF)


@pytest.fixture
def wallet_argon2() -> WalletResult:
    return derive_bip84_from_text(SAMPLE_TEXT, SAMPLE_PASS, kdf=KDF.ARGON2ID)


@pytest.fixture
def wallet_legacy() -> WalletResult:
    return derive_bip84_from_text(SAMPLE_TEXT, SAMPLE_PASS, kdf=KDF.LEGACY)


# =========================================================
# Entropy determinism
# =========================================================
class TestEntropy:
    def test_hkdf_deterministic(self):
        e1 = derive_entropy(SAMPLE_TEXT, SAMPLE_PASS, KDF.HKDF)
        e2 = derive_entropy(SAMPLE_TEXT, SAMPLE_PASS, KDF.HKDF)
        assert e1 == e2
        assert len(e1) == 32

    def test_argon2_deterministic(self):
        e1 = derive_entropy(SAMPLE_TEXT, SAMPLE_PASS, KDF.ARGON2ID)
        e2 = derive_entropy(SAMPLE_TEXT, SAMPLE_PASS, KDF.ARGON2ID)
        assert e1 == e2
        assert len(e1) == 32

    def test_legacy_deterministic(self):
        e1 = derive_entropy(SAMPLE_TEXT, SAMPLE_PASS, KDF.LEGACY)
        e2 = derive_entropy(SAMPLE_TEXT, SAMPLE_PASS, KDF.LEGACY)
        assert e1 == e2
        assert len(e1) == 32

    def test_different_kdfs_produce_different_entropy(self):
        e_hkdf = derive_entropy(SAMPLE_TEXT, SAMPLE_PASS, KDF.HKDF)
        e_argon = derive_entropy(SAMPLE_TEXT, SAMPLE_PASS, KDF.ARGON2ID)
        e_legacy = derive_entropy(SAMPLE_TEXT, SAMPLE_PASS, KDF.LEGACY)
        assert e_hkdf != e_argon
        assert e_hkdf != e_legacy
        assert e_argon != e_legacy

    def test_different_input_different_entropy(self):
        e1 = derive_entropy("aaa", "bbb", KDF.HKDF)
        e2 = derive_entropy("aab", "bbb", KDF.HKDF)
        assert e1 != e2

    def test_unicode_normalization(self):
        # é as precomposed vs decomposed
        text_nfc = "café"
        text_nfd = "café"
        e1 = derive_entropy(text_nfc, SAMPLE_PASS, KDF.HKDF)
        e2 = derive_entropy(text_nfd, SAMPLE_PASS, KDF.HKDF)
        assert e1 == e2, "NFC normalization should make these identical"


# =========================================================
# Base58Check
# =========================================================
class TestBase58:
    def test_roundtrip(self):
        payload = b"\x00" * 3 + b"\xde\xad\xbe\xef"
        encoded = b58check_encode(payload)
        decoded = b58check_decode(encoded)
        assert decoded == payload

    def test_invalid_checksum(self):
        payload = b"\x01\x02\x03\x04"
        encoded = b58check_encode(payload)
        # corrupt last char
        bad = encoded[:-1] + ("2" if encoded[-1] != "2" else "3")
        with pytest.raises(ValueError, match="Checksum"):
            b58check_decode(bad)


# =========================================================
# Wallet derivation
# =========================================================
class TestWalletDerivation:
    def test_mnemonic_24_words(self, wallet_hkdf):
        words = wallet_hkdf.mnemonic_24.split()
        assert len(words) == 24

    def test_addresses_start_with_bc1(self, wallet_hkdf):
        for _, addr in wallet_hkdf.external_addrs:
            assert addr.startswith("bc1q")
        for _, addr in wallet_hkdf.change_addrs:
            assert addr.startswith("bc1q")

    def test_address_count(self):
        r = derive_bip84_from_text(SAMPLE_TEXT, SAMPLE_PASS, kdf=KDF.HKDF, external_count=5, change_count=3)
        assert len(r.external_addrs) == 5
        assert len(r.change_addrs) == 3

    def test_xpub_starts_with_xpub(self, wallet_hkdf):
        assert wallet_hkdf.xpub.startswith("xpub")

    def test_zpub_starts_with_zpub(self, wallet_hkdf):
        assert wallet_hkdf.zpub.startswith("zpub")

    def test_kdf_recorded(self, wallet_hkdf, wallet_argon2, wallet_legacy):
        assert wallet_hkdf.kdf_used == "hkdf"
        assert wallet_argon2.kdf_used == "argon2id"
        assert wallet_legacy.kdf_used == "legacy"

    def test_empty_text_raises(self):
        with pytest.raises(ValueError, match="vazia"):
            derive_bip84_from_text("", SAMPLE_PASS, kdf=KDF.HKDF)

    def test_invalid_network_raises(self):
        with pytest.raises(ValueError, match="network"):
            derive_bip84_from_text(SAMPLE_TEXT, SAMPLE_PASS, kdf=KDF.HKDF, network="regtest")

    def test_testnet_addresses(self):
        r = derive_bip84_from_text(SAMPLE_TEXT, SAMPLE_PASS, kdf=KDF.HKDF, network="test", external_count=2, change_count=2)
        for _, addr in r.external_addrs:
            assert addr.startswith("tb1")

    def test_deterministic_across_calls(self):
        r1 = derive_bip84_from_text(SAMPLE_TEXT, SAMPLE_PASS, kdf=KDF.HKDF)
        r2 = derive_bip84_from_text(SAMPLE_TEXT, SAMPLE_PASS, kdf=KDF.HKDF)
        assert r1.mnemonic_24 == r2.mnemonic_24
        assert r1.xpub == r2.xpub
        assert r1.external_addrs == r2.external_addrs

    def test_descriptors_format(self, wallet_hkdf):
        assert wallet_hkdf.desc_external.startswith("wpkh([")
        assert "/0/*)" in wallet_hkdf.desc_external
        assert "/1/*)" in wallet_hkdf.desc_change


# =========================================================
# xpub → zpub
# =========================================================
class TestXpubToZpub:
    def test_zpub_roundtrip_consistency(self, wallet_hkdf):
        zpub = xpub_to_zpub(wallet_hkdf.xpub)
        assert zpub == wallet_hkdf.zpub
        assert zpub.startswith("zpub")


# =========================================================
# Exports
# =========================================================
class TestExports:
    def test_export_descriptors_txt(self, wallet_hkdf):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            path = f.name
        try:
            export_descriptors_txt(path, wallet_hkdf)
            content = open(path, encoding="utf-8").read()
            assert "wpkh(" in content
            assert wallet_hkdf.master_fingerprint_hex in content
            assert "kdf: hkdf" in content
        finally:
            os.unlink(path)

    def test_export_json(self, wallet_hkdf):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
        try:
            export_sparrow_like_json(path, wallet_hkdf)
            obj = json.loads(open(path, encoding="utf-8").read())
            assert obj["format"] == "infopass-bip84"
            assert obj["kdf"] == "hkdf"
            assert obj["xpub"].startswith("xpub")
            assert obj["zpub"].startswith("zpub")
            assert obj["first_addresses"]["external_0"].startswith("bc1")
        finally:
            os.unlink(path)


# =========================================================
# Unicode normalization
# =========================================================
class TestNormalize:
    def test_nfc(self):
        assert _normalize("café") == "café"
