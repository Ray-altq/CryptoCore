from __future__ import annotations


INITIAL_HASH = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]

ROUND_CONSTANTS = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]

MASK_32 = 0xFFFFFFFF
BLOCK_SIZE = 64


def _rotate_right(value: int, bits: int) -> int:
    return ((value >> bits) | (value << (32 - bits))) & MASK_32


class SHA256:
    def __init__(self) -> None:
        #рабочее состояние меняется после каждого полного блока
        self._hash = INITIAL_HASH.copy()
        self._buffer = bytearray()
        self._message_length = 0

    def update(self, data: bytes | bytearray | memoryview) -> SHA256:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("SHA256.update() requires a bytes-like object")

        part = bytes(data)
        self._message_length += len(part)
        self._buffer.extend(part)

        while len(self._buffer) >= BLOCK_SIZE:
            block = bytes(self._buffer[:BLOCK_SIZE])
            del self._buffer[:BLOCK_SIZE]
            self._process_block(block)

        return self

    def _process_block(self, block: bytes) -> None:
        words = [int.from_bytes(block[index:index + 4], "big") for index in range(0, 64, 4)]

        #первые 16 слов берутся из блока, остальные вычисляются из них
        for index in range(16, 64):
            word_15 = words[index - 15]
            word_2 = words[index - 2]
            sigma_0 = _rotate_right(word_15, 7) ^ _rotate_right(word_15, 18) ^ (word_15 >> 3)
            sigma_1 = _rotate_right(word_2, 17) ^ _rotate_right(word_2, 19) ^ (word_2 >> 10)
            words.append((words[index - 16] + sigma_0 + words[index - 7] + sigma_1) & MASK_32)

        a, b, c, d, e, f, g, h = self._hash

        for index in range(64):
            sum_1 = _rotate_right(e, 6) ^ _rotate_right(e, 11) ^ _rotate_right(e, 25)
            choose = (e & f) ^ ((~e) & g)
            temp_1 = (h + sum_1 + choose + ROUND_CONSTANTS[index] + words[index]) & MASK_32
            sum_0 = _rotate_right(a, 2) ^ _rotate_right(a, 13) ^ _rotate_right(a, 22)
            majority = (a & b) ^ (a & c) ^ (b & c)
            temp_2 = (sum_0 + majority) & MASK_32

            h = g
            g = f
            f = e
            e = (d + temp_1) & MASK_32
            d = c
            c = b
            b = a
            a = (temp_1 + temp_2) & MASK_32

        result = [a, b, c, d, e, f, g, h]
        self._hash = [(old + new) & MASK_32 for old, new in zip(self._hash, result)]

    def _copy(self) -> SHA256:
        other = SHA256()
        other._hash = self._hash.copy()
        other._buffer = self._buffer.copy()
        other._message_length = self._message_length
        return other

    def digest(self) -> bytes:
        #digest считается на копии, поэтому объект можно продолжить обновлять
        final = self._copy()
        tail = bytes(final._buffer) + b"\x80"
        tail += b"\x00" * ((56 - len(tail)) % BLOCK_SIZE)
        tail += (final._message_length * 8).to_bytes(8, "big")

        for index in range(0, len(tail), BLOCK_SIZE):
            final._process_block(tail[index:index + BLOCK_SIZE])

        return b"".join(value.to_bytes(4, "big") for value in final._hash)

    def hexdigest(self) -> str:
        return self.digest().hex()


def sha256(data: bytes | bytearray | memoryview) -> str:
    return SHA256().update(data).hexdigest()
