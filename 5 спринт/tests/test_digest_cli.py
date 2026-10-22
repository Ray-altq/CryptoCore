import hashlib
import io
from pathlib import Path

import pytest

from cryptocore.cli import DgstOptions, main, parse_digest_options


def test_dgst_args():  #тест для аргументов команды dgst
    options = parse_digest_options(
        ["--algorithm", "sha256", "--input", "document.pdf"]
    )

    assert options == DgstOptions(
        algorithm="sha256",
        input_file=Path("document.pdf"),
        output_file=None,
    )


def test_dgst_stdout(tmp_path: Path, capsys):  #тест для вывода SHA-256 в консоль
    source = tmp_path / "data.bin"
    source.write_bytes(b"hash from cli")

    code = main(["dgst", "--algorithm", "sha256", "--input", str(source)])
    output = capsys.readouterr()

    assert code == 0
    assert output.out == f"{hashlib.sha256(source.read_bytes()).hexdigest()}  {source}\n"
    assert output.err == ""


def test_dgst_output(tmp_path: Path, capsys):  #тест для записи SHA3-256 в файл
    source = tmp_path / "data.bin"
    result = tmp_path / "data.sha3"
    source.write_bytes(bytes(range(256)) * 40)

    code = main(
        [
            "dgst", "--algorithm", "sha3-256", "--input", str(source),
            "--output", str(result),
        ]
    )
    output = capsys.readouterr()

    expected = hashlib.sha3_256(source.read_bytes()).hexdigest()
    assert code == 0
    assert output.out == ""
    assert output.err == ""
    assert result.read_text(encoding="utf-8") == f"{expected}  {source}\n"


@pytest.mark.parametrize("option", ["--key", "--mode", "--iv", "--encrypt", "--decrypt"])
def test_dgst_rejects_cipher(option: str):  #тест для запрета параметров шифрования
    with pytest.raises(SystemExit):
        parse_digest_options(
            ["--algorithm", "sha256", "--input", "data.bin", option, "value"]
        )


def test_dgst_missing(tmp_path: Path, capsys):  #тест для отсутствующего файла
    source = tmp_path / "missing.bin"

    code = main(["dgst", "--algorithm", "sha256", "--input", str(source)])
    output = capsys.readouterr()

    assert code == 1
    assert output.out == ""
    assert "cryptocore: error:" in output.err
    assert str(source) in output.err


def test_dgst_stdin(monkeypatch, capsys):  #тест для чтения данных из stdin
    data = b"data from stdin"
    fake_stdin = io.TextIOWrapper(io.BytesIO(data), encoding="utf-8")
    monkeypatch.setattr("sys.stdin", fake_stdin)

    code = main(["dgst", "--algorithm", "sha256", "--input", "-"])
    output = capsys.readouterr()

    assert code == 0
    assert output.out == f"{hashlib.sha256(data).hexdigest()}  -\n"
