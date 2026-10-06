from pathlib import Path

import pytest

from cryptocore.file_io import add_iv, make_iv, read_binary_file, split_iv, write_binary_file


def test_read_bytes(tmp_path: Path):  #тест для чтения бинарного файла
    path = tmp_path / "data.bin"
    data = bytes(range(256))
    path.write_bytes(data)

    assert read_binary_file(path) == data


def test_write_bytes(tmp_path: Path):  #тест для записи бинарного файла
    path = tmp_path / "nested" / "data.bin"
    data = b"CryptoCore\x00\x01\x02"

    write_binary_file(path, data)

    assert path.read_bytes() == data


def test_read_missing_file(tmp_path: Path):  #тест для ошибки при отсутствующем файле
    path = tmp_path / "missing.bin"

    with pytest.raises(OSError) as error:
        read_binary_file(path)

    assert "failed to read input file" in str(error.value)


def test_make_iv():  #тест для генерации iv
    first_iv = make_iv()
    second_iv = make_iv()

    assert len(first_iv) == 16
    assert first_iv != second_iv


def test_iv_csprng(monkeypatch):  #тест для генерации iv через модуль csprng
    sizes = []

    def fake_random(num_bytes):
        sizes.append(num_bytes)
        return b"x" * num_bytes

    monkeypatch.setattr("cryptocore.file_io.generate_random_bytes", fake_random)

    assert make_iv() == b"x" * 16
    assert sizes == [16]


def test_add_iv():  #тест для записи iv перед шифротекстом
    iv = bytes(range(16))
    cipher = b"encrypted data"

    result = add_iv(iv, cipher)

    assert result == iv + cipher


def test_add_bad_iv():  #тест для ошибки при коротком iv
    with pytest.raises(ValueError):
        add_iv(b"short", b"data")


def test_split_iv():  #тест для чтения iv из начала файла
    iv = bytes(range(16))
    cipher = b"encrypted data"

    read_iv, read_cipher = split_iv(iv + cipher)

    assert read_iv == iv
    assert read_cipher == cipher


def test_short_iv_file():  #тест для ошибки при коротком файле
    with pytest.raises(ValueError):
        split_iv(b"short file")
