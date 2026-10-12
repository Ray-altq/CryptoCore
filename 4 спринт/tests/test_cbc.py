import pytest

from cryptocore.modes.cbc import decrypt_cbc, encrypt_cbc


KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


def test_known_block():  #тест для известного вектора cbc
    plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")

    ciphertext = encrypt_cbc(plaintext, KEY, IV)

    assert ciphertext[:16].hex() == "7649abac8119b246cee98e9b12e9197d"


def test_roundtrip():  #тест для шифрования и расшифрования cbc
    plaintext = bytes(range(256)) + b"CBC mode"

    ciphertext = encrypt_cbc(plaintext, KEY, IV)
    result = decrypt_cbc(ciphertext, KEY, IV)

    assert result == plaintext
    assert ciphertext != plaintext


def test_empty_data():  #тест для пустых данных cbc
    ciphertext = encrypt_cbc(b"", KEY, IV)

    assert decrypt_cbc(ciphertext, KEY, IV) == b""


def test_bad_iv():  #тест для ошибки при коротком iv
    with pytest.raises(ValueError):
        encrypt_cbc(b"data", KEY, b"short")


def test_bad_length():  #тест для ошибки при неверной длине шифротекста
    with pytest.raises(ValueError):
        decrypt_cbc(b"bad length", KEY, IV)
