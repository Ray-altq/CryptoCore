import pytest

from cryptocore.modes.ofb import decrypt_ofb, encrypt_ofb


KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


def test_known_blocks():  #тест для известных векторов ofb
    plaintext = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
    )

    ciphertext = encrypt_ofb(plaintext, KEY, IV)

    assert ciphertext.hex() == (
        "3b3fd92eb72dad20333449f8e83cfb4a"
        "7789508d16918f03f53c52dac54ed825"
    )


def test_roundtrip():  #тест для шифрования и расшифрования ofb
    plaintext = bytes(range(100)) + b"OFB mode"

    ciphertext = encrypt_ofb(plaintext, KEY, IV)
    result = decrypt_ofb(ciphertext, KEY, IV)

    assert result == plaintext
    assert len(ciphertext) == len(plaintext)


def test_partial_block():  #тест для неполного блока ofb
    plaintext = b"short data"

    ciphertext = encrypt_ofb(plaintext, KEY, IV)

    assert len(ciphertext) == len(plaintext)
    assert decrypt_ofb(ciphertext, KEY, IV) == plaintext


def test_empty_data():  #тест для пустых данных ofb
    assert encrypt_ofb(b"", KEY, IV) == b""
    assert decrypt_ofb(b"", KEY, IV) == b""


def test_bad_iv():  #тест для ошибки при коротком iv
    with pytest.raises(ValueError):
        encrypt_ofb(b"data", KEY, b"short")
