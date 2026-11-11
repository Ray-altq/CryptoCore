import hashlib

import pytest

from cryptocore.hashes.sha256 import SHA256, sha256


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
    ],
)
def test_vectors(data: bytes, expected: str):  #тест для известных векторов SHA-256
    assert sha256(data) == expected


def test_million_a():  #тест для длинного вектора NIST
    data = b"a" * 1_000_000

    assert sha256(data) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"


def test_chunks():  #тест для обновления хеша частями
    hasher = SHA256()
    hasher.update(b"abcdbcdecdefdefg")
    hasher.update(b"efghfghighijhijkijkljklmklmnlmnomnopnopq")

    assert hasher.hexdigest() == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"


def test_repeat_digest():  #тест для повторного получения результата
    hasher = SHA256().update(b"abc")

    assert hasher.digest() == hasher.digest()
    assert hasher.hexdigest() == sha256(b"abc")


def test_after_digest():  #тест для продолжения после digest
    hasher = SHA256().update(b"ab")
    hasher.digest()
    hasher.update(b"c")

    assert hasher.hexdigest() == sha256(b"abc")


def test_bad_type():  #тест для неверного типа данных
    with pytest.raises(TypeError):
        SHA256().update("abc")


@pytest.mark.parametrize("size", [55, 56, 57, 63, 64, 65, 119, 120, 121, 127, 128, 129])
def test_boundaries(size: int):  #тест для границ padding и блока SHA-256
    data = bytes((index * 7) % 256 for index in range(size))

    assert sha256(data) == hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize("chunk_size", [1, 55, 56, 63, 64, 65, 8192])
def test_chunk_sizes(chunk_size: int):  #тест для разных размеров частей входных данных
    data = bytes(range(256)) * 33
    hasher = SHA256()

    for index in range(0, len(data), chunk_size):
        hasher.update(data[index:index + chunk_size])

    assert hasher.digest() == hashlib.sha256(data).digest()
