from __future__ import annotations


RATE_BYTES = 136
MASK_64 = 0xFFFFFFFFFFFFFFFF

ROUND_CONSTANTS = [
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B,
    0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080,
    0x0000000080000001, 0x8000000080008008,
]

ROTATION_OFFSETS = [
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
]


def _rotate_left(value: int, bits: int) -> int:
    if bits == 0:
        return value
    return ((value << bits) | (value >> (64 - bits))) & MASK_64


def _keccak_f(state: list[int]) -> None:
    for round_constant in ROUND_CONSTANTS:
        #theta смешивает каждый столбец с двумя соседними
        columns = [
            state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
            for x in range(5)
        ]
        differences = [
            columns[(x - 1) % 5] ^ _rotate_left(columns[(x + 1) % 5], 1)
            for x in range(5)
        ]
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] ^= differences[x]

        #rho и pi поворачивают слова и переставляют их по матрице
        moved = [0] * 25
        for y in range(5):
            for x in range(5):
                new_x = y
                new_y = (2 * x + 3 * y) % 5
                index = x + 5 * y
                moved[new_x + 5 * new_y] = _rotate_left(state[index], ROTATION_OFFSETS[index])

        #chi нелинейно связывает слова в каждой строке
        for y in range(5):
            row = moved[5 * y:5 * y + 5]
            for x in range(5):
                state[x + 5 * y] = row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5])
                state[x + 5 * y] &= MASK_64

        state[0] ^= round_constant


class SHA3_256:
    def __init__(self) -> None:
        self._state = [0] * 25
        self._buffer = bytearray()

    def _absorb_block(self, block: bytes) -> None:
        for index in range(0, RATE_BYTES, 8):
            lane = int.from_bytes(block[index:index + 8], "little")
            self._state[index // 8] ^= lane
        _keccak_f(self._state)

    def update(self, data: bytes | bytearray | memoryview) -> SHA3_256:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("SHA3_256.update() requires a bytes-like object")

        self._buffer.extend(bytes(data))
        while len(self._buffer) >= RATE_BYTES:
            block = bytes(self._buffer[:RATE_BYTES])
            del self._buffer[:RATE_BYTES]
            self._absorb_block(block)

        return self

    def _copy(self) -> SHA3_256:
        other = SHA3_256()
        other._state = self._state.copy()
        other._buffer = self._buffer.copy()
        return other

    def digest(self) -> bytes:
        final = self._copy()

        #суффикс 0x06 отделяет SHA-3 от исходного Keccak
        padding_size = RATE_BYTES - len(final._buffer)
        padding = bytearray(padding_size)
        padding[0] = 0x06
        padding[-1] |= 0x80
        final._buffer.extend(padding)
        final._absorb_block(bytes(final._buffer))

        output = b"".join(value.to_bytes(8, "little") for value in final._state[:17])
        return output[:32]

    def hexdigest(self) -> str:
        return self.digest().hex()


def sha3_256(data: bytes | bytearray | memoryview) -> str:
    return SHA3_256().update(data).hexdigest()
