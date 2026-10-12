import pytest

from cryptocore.modes.ctr import decrypt_ctr, encrypt_ctr


KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
IV = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")


def test_known_blocks():  #тест для известных векторов ctr
    plaintext = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
    )

    ciphertext = encrypt_ctr(plaintext, KEY, IV)

    assert ciphertext.hex() == (
        "874d6191b620e3261bef6864990db6ce"
        "9806f66b7970fdff8617187bb9fffdff"
    )


def test_roundtrip():  #тест для шифрования и расшифрования ctr
    plaintext = bytes(range(100)) + b"CTR mode"

    ciphertext = encrypt_ctr(plaintext, KEY, IV)
    result = decrypt_ctr(ciphertext, KEY, IV)

    assert result == plaintext
    assert len(ciphertext) == len(plaintext)


def test_partial_block():  #тест для неполного блока ctr
    plaintext = b"last block"

    ciphertext = encrypt_ctr(plaintext, KEY, IV)

    assert len(ciphertext) == len(plaintext)
    assert decrypt_ctr(ciphertext, KEY, IV) == plaintext


def test_empty_data():  #тест для пустых данных ctr
    assert encrypt_ctr(b"", KEY, IV) == b""
    assert decrypt_ctr(b"", KEY, IV) == b""


def test_bad_iv():  #тест для ошибки при коротком iv
    with pytest.raises(ValueError):
        encrypt_ctr(b"data", KEY, b"short")
