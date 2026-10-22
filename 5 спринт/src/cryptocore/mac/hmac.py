from __future__ import annotations

from cryptocore.hashes.sha256 import BLOCK_SIZE, SHA256


class HMAC:
    def __init__(self, key: bytes | bytearray | memoryview) -> None:
        if not isinstance(key, (bytes, bytearray, memoryview)):
            raise TypeError("HMAC requires a bytes-like key")

        processed_key = bytes(key)
        #длинный ключ сначала хешируется, короткий дополняется нулями
        if len(processed_key) > BLOCK_SIZE:
            processed_key = SHA256().update(processed_key).digest()
        processed_key = processed_key.ljust(BLOCK_SIZE, b"\x00")

        inner_pad = bytes(value ^ 0x36 for value in processed_key)
        self._outer_pad = bytes(value ^ 0x5c for value in processed_key)
        self._inner = SHA256().update(inner_pad)

    def update(self, data: bytes | bytearray | memoryview) -> HMAC:
        self._inner.update(data)
        return self

    def digest(self) -> bytes:
        #внутреннее состояние не меняется, поэтому update можно продолжать
        inner_digest = self._inner.digest()
        return SHA256().update(self._outer_pad).update(inner_digest).digest()

    def hexdigest(self) -> str:
        return self.digest().hex()


def hmac_sha256(key: bytes | bytearray | memoryview, data: bytes | bytearray | memoryview) -> str:
    return HMAC(key).update(data).hexdigest()
