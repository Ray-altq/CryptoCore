import shutil
import subprocess
from pathlib import Path

import pytest

from cryptocore.modes.cbc import decrypt_cbc, encrypt_cbc
from cryptocore.modes.cfb import decrypt_cfb, encrypt_cfb
from cryptocore.modes.ctr import decrypt_ctr, encrypt_ctr
from cryptocore.modes.ofb import decrypt_ofb, encrypt_ofb


OPENSSL = shutil.which("openssl")
KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
IV = bytes.fromhex("101112131415161718191a1b1c1d1e1f")

MODES = [
    ("cbc", encrypt_cbc, decrypt_cbc),
    ("cfb", encrypt_cfb, decrypt_cfb),
    ("ofb", encrypt_ofb, decrypt_ofb),
    ("ctr", encrypt_ctr, decrypt_ctr),
]


@pytest.mark.skipif(OPENSSL is None, reason="OpenSSL is not installed")
@pytest.mark.parametrize("mode,encrypt,decrypt", MODES)
def test_openssl(mode, encrypt, decrypt, tmp_path: Path):  #тест для совместимости с openssl
    plain = tmp_path / "plain.bin"
    openssl_cipher = tmp_path / "openssl.bin"
    data = bytes(range(75)) + b"OpenSSL"
    plain.write_bytes(data)

    #openssl шифрует с тем же ключом и iv, соль здесь не используется
    subprocess.run(
        [
            OPENSSL,
            "enc",
            f"-aes-128-{mode}",
            "-K",
            KEY.hex(),
            "-iv",
            IV.hex(),
            "-nosalt",
            "-in",
            str(plain),
            "-out",
            str(openssl_cipher),
        ],
        check=True,
        capture_output=True,
    )

    expected = openssl_cipher.read_bytes()
    our_cipher = encrypt(data, KEY, IV)

    assert our_cipher == expected
    assert decrypt(expected, KEY, IV) == data
