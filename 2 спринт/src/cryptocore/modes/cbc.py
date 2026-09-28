from __future__ import annotations

from Crypto.Cipher import AES

from cryptocore.modes.ecb import BLOCK_SIZE, pkcs7_pad, pkcs7_unpad


def xor_blocks(first: bytes, second: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(first, second))


def check_iv(iv: bytes) -> None:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be exactly 16 bytes.")


def encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    check_iv(iv)
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pkcs7_pad(plaintext)
    result = bytearray()
    previous = iv

    #каждый блок зависит от предыдущего зашифрованного блока
    for offset in range(0, len(padded), BLOCK_SIZE):
        block = padded[offset : offset + BLOCK_SIZE]
        encrypted = cipher.encrypt(xor_blocks(block, previous))
        result.extend(encrypted)
        previous = encrypted

    return bytes(result)


def decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    check_iv(iv)
    if len(ciphertext) == 0 or len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("ciphertext length must be a non-empty multiple of 16 bytes.")

    cipher = AES.new(key, AES.MODE_ECB)
    result = bytearray()
    previous = iv

    for offset in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[offset : offset + BLOCK_SIZE]
        decrypted = xor_blocks(cipher.decrypt(block), previous)
        result.extend(decrypted)
        previous = block

    return pkcs7_unpad(bytes(result))
