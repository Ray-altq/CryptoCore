import pytest

from cryptocore.csprng import generate_random_bytes


def test_length():  #тест для длины случайных данных
    assert len(generate_random_bytes(16)) == 16
    assert len(generate_random_bytes(64)) == 64


def test_different():  #тест для разных результатов генерации
    first = generate_random_bytes(16)
    second = generate_random_bytes(16)

    assert first != second


def test_zero_size():  #тест для генерации пустой строки байтов
    assert generate_random_bytes(0) == b""


def test_bad_size():  #тест для ошибки при отрицательном размере
    with pytest.raises(ValueError):
        generate_random_bytes(-1)


def test_system_error(monkeypatch):  #тест для ошибки системного генератора
    def broken_urandom(num_bytes):
        raise OSError("random source is unavailable")

    monkeypatch.setattr("cryptocore.csprng.os.urandom", broken_urandom)

    with pytest.raises(RuntimeError, match="failed to get secure random bytes"):
        generate_random_bytes(16)
