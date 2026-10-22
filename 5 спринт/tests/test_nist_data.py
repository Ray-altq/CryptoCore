from pathlib import Path

import pytest

from scripts.generate_nist_data import generate_test_file


def test_nist_file(tmp_path: Path, monkeypatch):  #тест для подготовки файла nist sts
    output = tmp_path / "nist.bin"
    sizes = []

    def fake_random(num_bytes):
        sizes.append(num_bytes)
        return b"x" * num_bytes

    monkeypatch.setattr("scripts.generate_nist_data.generate_random_bytes", fake_random)

    written = generate_test_file(output, 9000)

    assert written == 9000
    assert output.read_bytes() == b"x" * 9000
    assert sizes == [4096, 4096, 808]


def test_nist_bad_size(tmp_path: Path):  #тест для ошибки при неверном размере файла
    with pytest.raises(ValueError):
        generate_test_file(tmp_path / "nist.bin", 0)
