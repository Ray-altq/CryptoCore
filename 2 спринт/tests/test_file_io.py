from pathlib import Path

import pytest

from cryptocore.file_io import read_binary_file, write_binary_file


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
