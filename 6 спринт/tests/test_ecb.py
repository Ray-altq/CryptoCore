import pytest

from cryptocore.modes.ecb import decrypt_ecb, encrypt_ecb, pkcs7_pad, pkcs7_unpad


KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


def test_pad_block():  #тест для padding на данных размером в полный блок
    assert pkcs7_pad(b"a" * 16) == b"a" * 16 + bytes([16]) * 16


def test_pad_short():  #тест для padding на неполном блоке
    assert pkcs7_pad(b"abc") == b"abc" + bytes([13]) * 13


def test_unpad_invalid():  #тест для ошибки при неверном padding
    with pytest.raises(ValueError):
        pkcs7_unpad(b"a" * 15 + b"\x02")


def test_roundtrip_binary():  #тест для полного цикла на бинарных данных
    plaintext = bytes(range(256)) + b"CryptoCore"

    ciphertext = encrypt_ecb(plaintext, KEY)
    decrypted = decrypt_ecb(ciphertext, KEY)

    assert decrypted == plaintext
    assert ciphertext != plaintext


def test_decrypt_bad_length():  #тест для ошибки при некратном размере шифротекста
    with pytest.raises(ValueError):
        decrypt_ecb(b"bad length", KEY)
