import hashlib
import hmac
import io
from pathlib import Path

import pytest

from cryptocore.cli import DgstOptions, main, parse_digest_options
from cryptocore.mac.file_mac import hmac_stream


def test_hmac_args():  #тест для аргументов dgst с HMAC
    key = bytes.fromhex("0b" * 20)
    options = parse_digest_options(
        ["--algorithm", "sha256", "--hmac", "--key", key.hex(), "--input", "message.txt"]
    )

    assert options == DgstOptions(
        algorithm="sha256",
        input_file=Path("message.txt"),
        output_file=None,
        hmac=True,
        key=key,
    )


def test_hmac_stdout(tmp_path: Path, capsys):  #тест для HMAC в консоль
    source = tmp_path / "message.txt"
    source.write_bytes(b"Hi There")
    key = b"\x0b" * 20

    code = main(
        [
            "dgst", "--algorithm", "sha256", "--hmac", "--key", key.hex(),
            "--input", str(source),
        ]
    )
    output = capsys.readouterr()

    expected = hmac.new(key, source.read_bytes(), hashlib.sha256).hexdigest()
    assert code == 0
    assert output.out == f"{expected}  {source}\n"
    assert output.err == ""


def test_hmac_output(tmp_path: Path, capsys):  #тест для записи HMAC в файл
    source = tmp_path / "message.bin"
    result = tmp_path / "message.hmac"
    source.write_bytes(bytes(range(256)) * 40)
    key = bytes(range(16))

    code = main(
        [
            "dgst", "--algorithm", "sha256", "--hmac", "--key", key.hex(),
            "--input", str(source), "--output", str(result),
        ]
    )
    output = capsys.readouterr()

    expected = hmac.new(key, source.read_bytes(), hashlib.sha256).hexdigest()
    assert code == 0
    assert output.out == ""
    assert output.err == ""
    assert result.read_text(encoding="utf-8") == f"{expected}  {source}\n"


def test_hmac_stdin(monkeypatch, capsys):  #тест для чтения данных из stdin
    data = b"data from stdin"
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    fake_stdin = io.TextIOWrapper(io.BytesIO(data), encoding="utf-8")
    monkeypatch.setattr("sys.stdin", fake_stdin)

    code = main(
        ["dgst", "--algorithm", "sha256", "--hmac", "--key", key.hex(), "--input", "-"]
    )
    output = capsys.readouterr()

    expected = hmac.new(key, data, hashlib.sha256).hexdigest()
    assert code == 0
    assert output.out == f"{expected}  -\n"


@pytest.mark.parametrize("size", [0, 1, 16, 64, 100])
def test_hmac_key_sizes(tmp_path: Path, capsys, size: int):  #тест для ключей разной длины
    source = tmp_path / "message.txt"
    source.write_bytes(b"key size test")
    key = bytes(range(size))

    code = main(
        [
            "dgst", "--algorithm", "sha256", "--hmac", "--key", key.hex(),
            "--input", str(source),
        ]
    )
    output = capsys.readouterr()

    expected = hmac.new(key, source.read_bytes(), hashlib.sha256).hexdigest()
    assert code == 0
    assert output.out == f"{expected}  {source}\n"


def test_hmac_empty_file(tmp_path: Path, capsys):  #тест для пустого файла
    source = tmp_path / "empty.bin"
    source.write_bytes(b"")
    key = b"secret"

    code = main(
        [
            "dgst", "--algorithm", "sha256", "--hmac", "--key", key.hex(),
            "--input", str(source),
        ]
    )
    output = capsys.readouterr()

    expected = hmac.new(key, b"", hashlib.sha256).hexdigest()
    assert code == 0
    assert output.out == f"{expected}  {source}\n"


def test_hmac_stream_chunks():  #тест для чтения потока маленькими частями
    class SmallChunks(io.BytesIO):
        def read(self, size=-1):
            return super().read(1 if size < 0 else min(size, 1))

    data = bytes(range(256)) * 33
    key = b"key" * 40

    assert hmac_stream(SmallChunks(data), key) == hmac.new(
        key, data, hashlib.sha256
    ).hexdigest()


def test_hmac_missing_key(tmp_path: Path, capsys):  #тест для обязательного ключа
    source = tmp_path / "message.txt"
    source.write_bytes(b"data")

    code = main(
        ["dgst", "--algorithm", "sha256", "--hmac", "--input", str(source)]
    )
    output = capsys.readouterr()

    assert code == 1
    assert output.out == ""
    assert "--key is required with --hmac" in output.err


def test_hmac_bad_key(tmp_path: Path, capsys):  #тест для неверной hex-строки ключа
    source = tmp_path / "message.txt"
    source.write_bytes(b"data")

    code = main(
        [
            "dgst", "--algorithm", "sha256", "--hmac", "--key", "not-hex",
            "--input", str(source),
        ]
    )
    output = capsys.readouterr()

    assert code == 1
    assert output.out == ""
    assert "must be a valid hexadecimal string" in output.err


def test_hmac_requires_sha256(tmp_path: Path, capsys):  #тест для HMAC только с SHA-256
    source = tmp_path / "message.txt"
    source.write_bytes(b"data")

    code = main(
        [
            "dgst", "--algorithm", "sha3-256", "--hmac", "--key", "00",
            "--input", str(source),
        ]
    )
    output = capsys.readouterr()

    assert code == 1
    assert output.out == ""
    assert "--hmac supports only sha256" in output.err


def test_key_requires_hmac(tmp_path: Path, capsys):  #тест для ключа без режима HMAC
    source = tmp_path / "message.txt"
    source.write_bytes(b"data")

    code = main(
        [
            "dgst", "--algorithm", "sha256", "--key", "00",
            "--input", str(source),
        ]
    )
    output = capsys.readouterr()

    assert code == 1
    assert output.out == ""
    assert "--key can only be used with --hmac" in output.err


def test_hmac_missing_file(tmp_path: Path, capsys):  #тест для отсутствующего файла
    source = tmp_path / "missing.bin"

    code = main(
        [
            "dgst", "--algorithm", "sha256", "--hmac", "--key", "00",
            "--input", str(source),
        ]
    )
    output = capsys.readouterr()

    assert code == 1
    assert output.out == ""
    assert "cryptocore: error:" in output.err
    assert str(source) in output.err


def make_hmac_file(path: Path, data: bytes, key: bytes) -> Path:
    path.write_bytes(data)
    expected = path.with_suffix(".hmac")
    expected.write_text(
        f"{hmac.new(key, data, hashlib.sha256).hexdigest()}  {path}\n",
        encoding="utf-8",
    )
    return expected


def test_verify_success(tmp_path: Path, capsys):  #тест для успешной проверки HMAC
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    source = tmp_path / "message.txt"
    expected = make_hmac_file(source, b"authentic message", key)

    code = main(
        [
            "dgst", "--algorithm", "sha256", "--hmac", "--key", key.hex(),
            "--input", str(source), "--verify", str(expected),
        ]
    )
    output = capsys.readouterr()

    assert code == 0
    assert output.out == "[OK] HMAC verification successful\n"
    assert output.err == ""


def test_verify_value_only(tmp_path: Path, capsys):  #тест для файла только со значением
    key = b"secret"
    source = tmp_path / "message.txt"
    expected = make_hmac_file(source, b"payload", key)
    expected.write_text(
        expected.read_text(encoding="utf-8").split()[0], encoding="utf-8"
    )

    code = main(
        [
            "dgst", "--algorithm", "sha256", "--hmac", "--key", key.hex(),
            "--input", str(source), "--verify", str(expected),
        ]
    )
    output = capsys.readouterr()

    assert code == 0
    assert output.out == "[OK] HMAC verification successful\n"


def test_verify_ignores_case(tmp_path: Path, capsys):  #тест для регистра и пробелов
    key = b"secret"
    source = tmp_path / "message.txt"
    expected = make_hmac_file(source, b"payload", key)
    expected.write_text(
        f"  {expected.read_text(encoding='utf-8').split()[0].upper()}  \n",
        encoding="utf-8",
    )

    code = main(
        [
            "dgst", "--algorithm", "sha256", "--hmac", "--key", key.hex(),
            "--input", str(source), "--verify", str(expected),
        ]
    )
    output = capsys.readouterr()

    assert code == 0
    assert output.out == "[OK] HMAC verification successful\n"


def test_verify_tampered_file(tmp_path: Path, capsys):  #тест для измененного файла
    key = b"secret"
    source = tmp_path / "message.txt"
    expected = make_hmac_file(source, b"original content", key)
    source.write_bytes(b"modified content")

    code = main(
        [
            "dgst", "--algorithm", "sha256", "--hmac", "--key", key.hex(),
            "--input", str(source), "--verify", str(expected),
        ]
    )
    output = capsys.readouterr()

    assert code == 1
    assert output.out == ""
    assert output.err == "[ERROR] HMAC verification failed\n"


def test_verify_wrong_key(tmp_path: Path, capsys):  #тест для неверного ключа
    source = tmp_path / "message.txt"
    expected = make_hmac_file(source, b"content", b"first key")

    code = main(
        [
            "dgst", "--algorithm", "sha256", "--hmac", "--key", b"second key".hex(),
            "--input", str(source), "--verify", str(expected),
        ]
    )
    output = capsys.readouterr()

    assert code == 1
    assert output.out == ""
    assert output.err == "[ERROR] HMAC verification failed\n"


def test_verify_bad_value(tmp_path: Path, capsys):  #тест для мусора вместо HMAC
    key = b"secret"
    source = tmp_path / "message.txt"
    source.write_bytes(b"content")
    expected = tmp_path / "message.hmac"
    expected.write_text("not-a-hex-value  message.txt\n", encoding="utf-8")

    code = main(
        [
            "dgst", "--algorithm", "sha256", "--hmac", "--key", key.hex(),
            "--input", str(source), "--verify", str(expected),
        ]
    )
    output = capsys.readouterr()

    assert code == 1
    assert output.out == ""
    assert output.err == "[ERROR] HMAC verification failed\n"


def test_verify_empty_file(tmp_path: Path, capsys):  #тест для пустого файла с HMAC
    key = b"secret"
    source = tmp_path / "message.txt"
    source.write_bytes(b"content")
    expected = tmp_path / "message.hmac"
    expected.write_text("", encoding="utf-8")

    code = main(
        [
            "dgst", "--algorithm", "sha256", "--hmac", "--key", key.hex(),
            "--input", str(source), "--verify", str(expected),
        ]
    )
    output = capsys.readouterr()

    assert code == 1
    assert output.out == ""
    assert "is empty" in output.err


def test_verify_missing_file(tmp_path: Path, capsys):  #тест для отсутствующего файла с HMAC
    key = b"secret"
    source = tmp_path / "message.txt"
    source.write_bytes(b"content")

    code = main(
        [
            "dgst", "--algorithm", "sha256", "--hmac", "--key", key.hex(),
            "--input", str(source), "--verify", str(tmp_path / "missing.hmac"),
        ]
    )
    output = capsys.readouterr()

    assert code == 1
    assert output.out == ""
    assert "failed to read HMAC file" in output.err


def test_verify_requires_hmac(tmp_path: Path, capsys):  #тест для --verify без HMAC
    source = tmp_path / "message.txt"
    source.write_bytes(b"content")

    code = main(
        [
            "dgst", "--algorithm", "sha256", "--input", str(source),
            "--verify", str(tmp_path / "message.hmac"),
        ]
    )
    output = capsys.readouterr()

    assert code == 1
    assert output.out == ""
    assert "--verify can only be used with --hmac" in output.err


def test_verify_rejects_output(tmp_path: Path, capsys):  #тест для --verify вместе с --output
    key = b"secret"
    source = tmp_path / "message.txt"
    source.write_bytes(b"content")

    code = main(
        [
            "dgst", "--algorithm", "sha256", "--hmac", "--key", key.hex(),
            "--input", str(source), "--verify", str(tmp_path / "message.hmac"),
            "--output", str(tmp_path / "result.txt"),
        ]
    )
    output = capsys.readouterr()

    assert code == 1
    assert output.out == ""
    assert "--output cannot be used with --verify" in output.err
