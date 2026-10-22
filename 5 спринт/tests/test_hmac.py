import hashlib
import hmac

import pytest

from cryptocore.mac.hmac import HMAC, hmac_sha256


@pytest.mark.parametrize(
    ("key", "data", "expected"),
    [
        (b"\x0b" * 20, b"Hi There", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        (b"Jefe", b"what do ya want for nothing?", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
        (b"\xaa" * 20, b"\xdd" * 50, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
        (bytes(range(1, 26)), b"\xcd" * 50, "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
    ],
)
def test_rfc_vectors(key: bytes, data: bytes, expected: str):  #тест для первых четырёх векторов RFC 4231
    assert hmac_sha256(key, data) == expected


@pytest.mark.parametrize("key_size", [0, 1, 16, 63, 64, 65, 100, 131])
@pytest.mark.parametrize("data", [b"", b"abc", bytes(range(256))])
def test_key_sizes(key_size: int, data: bytes):  #тест для коротких, полных и длинных ключей
    key = bytes(range(key_size))

    assert hmac_sha256(key, data) == hmac.new(key, data, hashlib.sha256).hexdigest()


@pytest.mark.parametrize("chunk_size", [1, 63, 64, 65, 8192])
def test_chunks(chunk_size: int):  #тест для обновления HMAC частями
    key = b"key" * 40
    data = bytes(range(256)) * 33
    mac = HMAC(key)

    for index in range(0, len(data), chunk_size):
        mac.update(data[index:index + chunk_size])

    assert mac.digest() == hmac.new(key, data, hashlib.sha256).digest()


def test_after_digest():  #тест для повторного digest и продолжения обновления
    mac = HMAC(b"key").update(b"ab")
    expected = hmac.new(b"key", b"ab", hashlib.sha256).digest()

    assert mac.digest() == mac.digest() == expected
    mac.update(b"c")

    assert mac.hexdigest() == hmac.new(b"key", b"abc", hashlib.sha256).hexdigest()


@pytest.mark.parametrize("value", ["key", 16, None])
def test_bad_key(value):  #тест для неверного типа ключа
    with pytest.raises(TypeError):
        HMAC(value)


def test_bad_data():  #тест для неверного типа сообщения
    with pytest.raises(TypeError):
        HMAC(b"key").update("abc")


def test_bytes_like():  #тест для ключа и сообщения в изменяемых буферах
    assert hmac_sha256(bytearray(b"key"), memoryview(b"abc")) == hmac.new(b"key", b"abc", hashlib.sha256).hexdigest()
