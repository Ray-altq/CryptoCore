from __future__ import annotations

from Crypto.Cipher import AES

from cryptocore.modes.ecb import BLOCK_SIZE


def check_iv(iv: bytes) -> None:
    #для aes нужен iv размером в один блок
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be exactly 16 bytes.")


def xor_data(data: bytes, gamma: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, gamma))


def crypt_ofb(data: bytes, key: bytes, iv: bytes) -> bytes:
    check_iv(iv)
    cipher = AES.new(key, AES.MODE_ECB)
    result = bytearray()
    gamma = iv

    #в ofb каждый раз шифруем прошлую гамму, а не данные
    for offset in range(0, len(data), BLOCK_SIZE):
        block = data[offset : offset + BLOCK_SIZE]
        gamma = cipher.encrypt(gamma)
        result.extend(xor_data(block, gamma))

    return bytes(result)


def encrypt_ofb(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    #для шифрования и расшифрования используется одна операция
    return crypt_ofb(plaintext, key, iv)


def decrypt_ofb(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    return crypt_ofb(ciphertext, key, iv)
