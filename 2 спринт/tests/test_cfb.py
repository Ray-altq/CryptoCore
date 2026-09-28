import pytest

from cryptocore.modes.cfb import decrypt_cfb, encrypt_cfb


KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


def test_known_block():  #тест для известного вектора cfb
    plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")

    ciphertext = encrypt_cfb(plaintext, KEY, IV)

    assert ciphertext.hex() == "3b3fd92eb72dad20333449f8e83cfb4a"


def test_roundtrip():  #тест для шифрования и расшифрования cfb
    plaintext = bytes(range(100)) + b"CFB mode"

    ciphertext = encrypt_cfb(plaintext, KEY, IV)
    result = decrypt_cfb(ciphertext, KEY, IV)

    assert result == plaintext
    assert len(ciphertext) == len(plaintext)


def test_partial_block():  #тест для неполного блока cfb
    plaintext = b"seven!!"

    ciphertext = encrypt_cfb(plaintext, KEY, IV)

    assert len(ciphertext) == 7
    assert decrypt_cfb(ciphertext, KEY, IV) == plaintext


def test_empty_data():  #тест для пустых данных cfb
    assert encrypt_cfb(b"", KEY, IV) == b""
    assert decrypt_cfb(b"", KEY, IV) == b""


def test_bad_iv():  #тест для ошибки при коротком iv
    with pytest.raises(ValueError):
        encrypt_cfb(b"data", KEY, b"short")
