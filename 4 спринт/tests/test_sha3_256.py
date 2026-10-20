import hashlib

import pytest

from cryptocore.hashes.sha3_256 import SHA3_256, sha3_256


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
        (b"abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376",
        ),
    ],
)
def test_vectors(data: bytes, expected: str):  #тест для известных векторов SHA3-256
    assert sha3_256(data) == expected


def test_million_a():  #тест для длинного вектора NIST
    data = b"a" * 1_000_000

    assert sha3_256(data) == "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1"


def test_chunks():  #тест для обновления SHA3-256 частями
    data = bytes((index * 19) % 256 for index in range(500))
    hasher = SHA3_256()

    for index in range(0, len(data), 31):
        hasher.update(data[index:index + 31])

    assert hasher.hexdigest() == hashlib.sha3_256(data).hexdigest()


@pytest.mark.parametrize("size", [135, 136, 137, 271, 272, 273])
def test_boundaries(size: int):  #тест для границ блока Keccak
    data = bytes((index * 7) % 256 for index in range(size))

    assert sha3_256(data) == hashlib.sha3_256(data).hexdigest()


def test_after_digest():  #тест для продолжения после digest
    hasher = SHA3_256().update(b"ab")
    hasher.digest()
    hasher.update(b"c")

    assert hasher.hexdigest() == sha3_256(b"abc")


def test_bad_type():  #тест для неверного типа данных
    with pytest.raises(TypeError):
        SHA3_256().update("abc")


@pytest.mark.parametrize("chunk_size", [1, 135, 136, 137, 8192])
def test_chunk_sizes(chunk_size: int):  #тест для разных размеров частей входных данных
    data = bytes(range(256)) * 33
    hasher = SHA3_256()

    for index in range(0, len(data), chunk_size):
        hasher.update(data[index:index + chunk_size])

    assert hasher.digest() == hashlib.sha3_256(data).digest()
