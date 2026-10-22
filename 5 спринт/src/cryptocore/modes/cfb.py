from __future__ import annotations

from Crypto.Cipher import AES

from cryptocore.modes.ecb import BLOCK_SIZE


def check_iv(iv: bytes) -> None:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be exactly 16 bytes.")


def xor_data(data: bytes, gamma: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, gamma))


def encrypt_cfb(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    check_iv(iv)
    cipher = AES.new(key, AES.MODE_ECB)
    result = bytearray()
    previous = iv

    #в cfb шифруется предыдущий блок, padding не нужен
    for offset in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[offset : offset + BLOCK_SIZE]
        gamma = cipher.encrypt(previous)
        encrypted = xor_data(block, gamma)
        result.extend(encrypted)
        previous = encrypted

    return bytes(result)


def decrypt_cfb(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    check_iv(iv)
    cipher = AES.new(key, AES.MODE_ECB)
    result = bytearray()
    previous = iv

    for offset in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[offset : offset + BLOCK_SIZE]
        gamma = cipher.encrypt(previous)
        result.extend(xor_data(block, gamma))
        previous = block

    return bytes(result)
