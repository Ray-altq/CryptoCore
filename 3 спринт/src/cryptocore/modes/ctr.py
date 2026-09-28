from __future__ import annotations

from Crypto.Cipher import AES

from cryptocore.modes.ecb import BLOCK_SIZE


MAX_COUNTER = 1 << (BLOCK_SIZE * 8)


def check_iv(iv: bytes) -> None:
    #iv используется как начальное значение счетчика
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be exactly 16 bytes.")


def xor_data(data: bytes, gamma: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, gamma))


def crypt_ctr(data: bytes, key: bytes, iv: bytes) -> bytes:
    check_iv(iv)
    cipher = AES.new(key, AES.MODE_ECB)
    result = bytearray()
    counter = int.from_bytes(iv, "big")

    #шифруем счетчик и увеличиваем его после каждого блока
    for offset in range(0, len(data), BLOCK_SIZE):
        block = data[offset : offset + BLOCK_SIZE]
        counter_bytes = counter.to_bytes(BLOCK_SIZE, "big")
        gamma = cipher.encrypt(counter_bytes)
        result.extend(xor_data(block, gamma))
        counter = (counter + 1) % MAX_COUNTER

    return bytes(result)


def encrypt_ctr(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    #в ctr шифрование и расшифрование одинаковые
    return crypt_ctr(plaintext, key, iv)


def decrypt_ctr(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    return crypt_ctr(ciphertext, key, iv)
