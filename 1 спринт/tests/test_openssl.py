import shutil
import subprocess
from pathlib import Path

import pytest

from cryptocore.cli import main


OPENSSL = shutil.which("openssl")
KEY = "000102030405060708090a0b0c0d0e0f"


@pytest.mark.skipif(OPENSSL is None, reason="OpenSSL is not installed")
def test_to_openssl(tmp_path: Path):  #тест для расшифрования файла cryptocore в openssl
    plain = tmp_path / "plain.bin"
    cipher = tmp_path / "cipher.bin"
    result = tmp_path / "result.bin"
    data = bytes(range(75)) + b"OpenSSL ECB"
    plain.write_bytes(data)

    code = main(
        [
            "--algorithm", "aes", "--mode", "ecb", "--encrypt",
            "--key", KEY, "--input", str(plain), "--output", str(cipher),
        ]
    )

    #openssl должен снять тот же padding и получить исходный файл
    subprocess.run(
        [
            OPENSSL,
            "enc",
            "-d",
            "-aes-128-ecb",
            "-K",
            KEY,
            "-nosalt",
            "-in",
            str(cipher),
            "-out",
            str(result),
        ],
        check=True,
        capture_output=True,
    )

    assert code == 0
    assert result.read_bytes() == data


@pytest.mark.skipif(OPENSSL is None, reason="OpenSSL is not installed")
def test_from_openssl(tmp_path: Path):  #тест для расшифрования файла openssl в cryptocore
    plain = tmp_path / "plain.bin"
    cipher = tmp_path / "cipher.bin"
    result = tmp_path / "result.bin"
    data = bytes(range(75)) + b"CryptoCore ECB"
    plain.write_bytes(data)

    subprocess.run(
        [
            OPENSSL,
            "enc",
            "-aes-128-ecb",
            "-K",
            KEY,
            "-nosalt",
            "-in",
            str(plain),
            "-out",
            str(cipher),
        ],
        check=True,
        capture_output=True,
    )

    code = main(
        [
            "--algorithm", "aes", "--mode", "ecb", "--decrypt",
            "--key", KEY, "--input", str(cipher), "--output", str(result),
        ]
    )

    assert code == 0
    assert result.read_bytes() == data
