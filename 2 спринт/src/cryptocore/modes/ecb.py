from __future__ import annotations

from Crypto.Cipher import AES


BLOCK_SIZE = AES.block_size


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    #добавляем padding даже если данные уже кратны размеру блока
    if block_size <= 0 or block_size > 255:
        raise ValueError("block size must be in range 1..255.")

    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len]) * padding_len


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    #проверяем padding перед удалением, чтобы не принимать битые данные
    if not data:
        raise ValueError("invalid PKCS#7 padding: empty input.")
    if len(data) % block_size != 0:
        raise ValueError("invalid PKCS#7 padding: data length is not block-aligned.")

    padding_len = data[-1]
    if padding_len < 1 or padding_len > block_size:
        raise ValueError("invalid PKCS#7 padding length.")
    if data[-padding_len:] != bytes([padding_len]) * padding_len:
        raise ValueError("invalid PKCS#7 padding bytes.")

    return data[:-padding_len]


def encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pkcs7_pad(plaintext)

    #режим ECB реализован здесь через явную обработку каждого блока
    return b"".join(
        cipher.encrypt(padded[offset : offset + BLOCK_SIZE])
        for offset in range(0, len(padded), BLOCK_SIZE)
    )


def decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes:
    if len(ciphertext) == 0 or len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("ciphertext length must be a non-empty multiple of 16 bytes.")

    cipher = AES.new(key, AES.MODE_ECB)

    #после расшифрования убираем PKCS#7 padding
    padded_plaintext = b"".join(
        cipher.decrypt(ciphertext[offset : offset + BLOCK_SIZE])
        for offset in range(0, len(ciphertext), BLOCK_SIZE)
    )
    return pkcs7_unpad(padded_plaintext)
