import shutil
import subprocess
from pathlib import Path

import pytest

from cryptocore.cli import main


OPENSSL = shutil.which("openssl")
KEY = "000102030405060708090a0b0c0d0e0f"
IV = "101112131415161718191a1b1c1d1e1f"
MODES = ["cbc", "cfb", "ofb", "ctr"]


@pytest.mark.skipif(OPENSSL is None, reason="OpenSSL is not installed")
@pytest.mark.parametrize("mode", MODES)
def test_to_openssl(mode: str, tmp_path: Path):  #тест для расшифрования файла cryptocore в openssl
    plain = tmp_path / "plain.bin"
    packed = tmp_path / "packed.bin"
    cipher = tmp_path / "cipher.bin"
    result = tmp_path / "result.bin"
    data = bytes(range(75)) + b"OpenSSL"
    plain.write_bytes(data)

    code = main(
        [
            "--algorithm", "aes", "--mode", mode, "--encrypt",
            "--key", KEY, "--input", str(plain), "--output", str(packed),
        ]
    )

    #отделяем iv от шифротекста перед передачей в openssl
    packed_data = packed.read_bytes()
    iv = packed_data[:16]
    cipher.write_bytes(packed_data[16:])

    subprocess.run(
        [
            OPENSSL,
            "enc",
            "-d",
            f"-aes-128-{mode}",
            "-K",
            KEY,
            "-iv",
            iv.hex(),
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
@pytest.mark.parametrize("mode", MODES)
def test_from_openssl(mode: str, tmp_path: Path):  #тест для расшифрования файла openssl в cryptocore
    plain = tmp_path / "plain.bin"
    cipher = tmp_path / "cipher.bin"
    result = tmp_path / "result.bin"
    data = bytes(range(75)) + b"CryptoCore"
    plain.write_bytes(data)

    #openssl создает обычный шифротекст без iv в начале
    subprocess.run(
        [
            OPENSSL,
            "enc",
            f"-aes-128-{mode}",
            "-K",
            KEY,
            "-iv",
            IV,
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
            "--algorithm", "aes", "--mode", mode, "--decrypt",
            "--key", KEY, "--iv", IV,
            "--input", str(cipher), "--output", str(result),
        ]
    )

    assert code == 0
    assert result.read_bytes() == data
