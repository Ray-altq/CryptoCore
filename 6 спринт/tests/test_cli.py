from pathlib import Path

import pytest

from cryptocore.cli import CliError, is_weak_key, main, parse_iv, parse_key, parse_options


def test_encrypt_args():  #тест для обязательных аргументов шифрования
    options = parse_options(
        [
            "--algorithm",
            "aes",
            "--mode",
            "ecb",
            "--encrypt",
            "--key",
            "000102030405060708090a0b0c0d0e0f",
            "--input",
            "plain.txt",
            "--output",
            "cipher.bin",
        ]
    )

    assert options.algorithm == "aes"
    assert options.mode == "ecb"
    assert options.encrypt is True
    assert options.decrypt is False
    assert options.key == bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    assert options.iv is None
    assert options.input_file == Path("plain.txt")
    assert options.output_file == Path("cipher.bin")


def test_decrypt_args():  #тест для обязательных аргументов расшифрования
    options = parse_options(
        [
            "--algorithm",
            "aes",
            "--mode",
            "ecb",
            "--decrypt",
            "--key",
            "000102030405060708090a0b0c0d0e0f",
            "--input",
            "cipher.bin",
            "--output",
            "plain.txt",
        ]
    )

    assert options.encrypt is False
    assert options.decrypt is True


def test_encrypt_no_key():  #тест для необязательного ключа при шифровании
    options = parse_options(
        [
            "--algorithm", "aes", "--mode", "ctr", "--encrypt",
            "--input", "plain.txt", "--output", "cipher.bin",
        ]
    )

    assert options.key is None


def test_decrypt_no_key(capsys):  #тест для обязательного ключа при расшифровании
    code = main(
        [
            "--algorithm", "aes", "--mode", "ctr", "--decrypt",
            "--input", "cipher.bin", "--output", "plain.txt",
        ]
    )

    error = capsys.readouterr().err

    assert code == 1
    assert "--key is required for decryption" in error


def test_new_mode_args():  #тест для новых режимов второго спринта
    for mode in ["cbc", "cfb", "ofb", "ctr"]:
        options = parse_options(
            [
                "--algorithm",
                "aes",
                "--mode",
                mode,
                "--encrypt",
                "--key",
                "000102030405060708090a0b0c0d0e0f",
                "--input",
                "plain.txt",
                "--output",
                "cipher.bin",
            ]
        )

        assert options.mode == mode


def test_operation_conflict():  #тест для запрета одновременных encrypt и decrypt
    with pytest.raises(SystemExit):
        parse_options(
            [
                "--algorithm",
                "aes",
                "--mode",
                "ecb",
                "--encrypt",
                "--decrypt",
                "--key",
                "000102030405060708090a0b0c0d0e0f",
                "--input",
                "plain.txt",
                "--output",
                "cipher.bin",
            ]
        )


def test_key_not_hex():  #тест для ошибки при не hex-ключе
    with pytest.raises(CliError):
        parse_key("not-a-hex-key")


def test_key_length():  #тест для ошибки при неверной длине ключа
    with pytest.raises(CliError):
        parse_key("abcd")


def test_weak_keys():  #тест для определения слабых ключей
    assert is_weak_key(bytes(16)) is True
    assert is_weak_key(bytes(range(16))) is True


def test_normal_key():  #тест для обычного ключа
    key = bytes.fromhex("a13f994e207bc81672d50a61ee38b745")

    assert is_weak_key(key) is False


def test_iv_hex():  #тест для разбора iv
    iv = parse_iv("aabbccddeeff00112233445566778899")

    assert iv == bytes.fromhex("aabbccddeeff00112233445566778899")


def test_iv_length():  #тест для ошибки при неверной длине iv
    with pytest.raises(CliError):
        parse_iv("abcd")


def test_iv_encrypt_error():  #тест для запрета iv при шифровании
    with pytest.raises(CliError):
        parse_options(
            [
                "--algorithm",
                "aes",
                "--mode",
                "cbc",
                "--encrypt",
                "--key",
                "000102030405060708090a0b0c0d0e0f",
                "--iv",
                "aabbccddeeff00112233445566778899",
                "--input",
                "plain.txt",
                "--output",
                "cipher.bin",
            ]
        )


def test_iv_decrypt_args():  #тест для iv при расшифровании
    options = parse_options(
        [
            "--algorithm",
            "aes",
            "--mode",
            "cbc",
            "--decrypt",
            "--key",
            "000102030405060708090a0b0c0d0e0f",
            "--iv",
            "aabbccddeeff00112233445566778899",
            "--input",
            "cipher.bin",
            "--output",
            "plain.txt",
        ]
    )

    assert options.iv == bytes.fromhex("aabbccddeeff00112233445566778899")


def test_iv_ecb_error():  #тест для запрета iv в режиме ecb
    with pytest.raises(CliError):
        parse_options(
            [
                "--algorithm",
                "aes",
                "--mode",
                "ecb",
                "--decrypt",
                "--key",
                "000102030405060708090a0b0c0d0e0f",
                "--iv",
                "aabbccddeeff00112233445566778899",
                "--input",
                "cipher.bin",
                "--output",
                "plain.txt",
            ]
        )


def test_cli_roundtrip(tmp_path: Path):  #тест для полного цикла через cli
    plain = tmp_path / "plain.bin"
    cipher = tmp_path / "cipher.bin"
    result = tmp_path / "result.bin"
    data = b"hello cryptocore\n\x00\x01\x02"
    key = "000102030405060708090a0b0c0d0e0f"
    plain.write_bytes(data)

    enc_code = main(
        [
            "--algorithm",
            "aes",
            "--mode",
            "ecb",
            "--encrypt",
            "--key",
            key,
            "--input",
            str(plain),
            "--output",
            str(cipher),
        ]
    )
    dec_code = main(
        [
            "--algorithm",
            "aes",
            "--mode",
            "ecb",
            "--decrypt",
            "--key",
            key,
            "--input",
            str(cipher),
            "--output",
            str(result),
        ]
    )

    assert enc_code == 0
    assert dec_code == 0
    assert result.read_bytes() == data


def test_generated_key(tmp_path: Path, monkeypatch, capsys):  #тест для полного цикла со случайным ключом
    plain = tmp_path / "plain.bin"
    cipher = tmp_path / "cipher.bin"
    result = tmp_path / "result.bin"
    data = b"generated key roundtrip"
    generated_key = b"\xab" * 16
    plain.write_bytes(data)

    monkeypatch.setattr("cryptocore.cli.generate_random_bytes", lambda size: generated_key)

    enc_code = main(
        [
            "--algorithm", "aes", "--mode", "ctr", "--encrypt",
            "--input", str(plain), "--output", str(cipher),
        ]
    )
    output = capsys.readouterr().out

    dec_code = main(
        [
            "--algorithm", "aes", "--mode", "ctr", "--decrypt",
            "--key", generated_key.hex(),
            "--input", str(cipher), "--output", str(result),
        ]
    )

    assert enc_code == 0
    assert output == f"[INFO] Generated random key: {generated_key.hex()}\n"
    assert cipher.stat().st_size == len(data) + 16
    assert dec_code == 0
    assert result.read_bytes() == data


def test_weak_warning(tmp_path: Path, capsys):  #тест для предупреждения о слабом ключе
    plain = tmp_path / "plain.bin"
    cipher = tmp_path / "cipher.bin"
    plain.write_bytes(b"weak key test")

    code = main(
        [
            "--algorithm", "aes", "--mode", "ecb", "--encrypt",
            "--key", "00000000000000000000000000000000",
            "--input", str(plain), "--output", str(cipher),
        ]
    )
    output = capsys.readouterr()

    assert code == 0
    assert output.out == ""
    assert output.err == "[WARNING] Weak key detected.\n"


def test_cli_new_modes(tmp_path: Path):  #тест для полного цикла новых режимов
    plain = tmp_path / "plain.bin"
    cipher = tmp_path / "cipher.bin"
    result = tmp_path / "result.bin"
    data = bytes(range(100)) + b"new modes"
    key = "000102030405060708090a0b0c0d0e0f"
    plain.write_bytes(data)

    for mode in ["cbc", "cfb", "ofb", "ctr"]:
        enc_code = main(
            [
                "--algorithm", "aes", "--mode", mode, "--encrypt",
                "--key", key, "--input", str(plain), "--output", str(cipher),
            ]
        )
        dec_code = main(
            [
                "--algorithm", "aes", "--mode", mode, "--decrypt",
                "--key", key, "--input", str(cipher), "--output", str(result),
            ]
        )

        assert enc_code == 0
        assert dec_code == 0
        assert result.read_bytes() == data
        assert cipher.stat().st_size >= len(data) + 16


def test_cli_given_iv(tmp_path: Path):  #тест для расшифрования с переданным iv
    plain = tmp_path / "plain.bin"
    packed = tmp_path / "packed.bin"
    cipher = tmp_path / "cipher.bin"
    result = tmp_path / "result.bin"
    data = b"decrypt with given iv"
    key = "000102030405060708090a0b0c0d0e0f"
    plain.write_bytes(data)

    main(
        [
            "--algorithm", "aes", "--mode", "cfb", "--encrypt",
            "--key", key, "--input", str(plain), "--output", str(packed),
        ]
    )
    packed_data = packed.read_bytes()
    iv = packed_data[:16]
    cipher.write_bytes(packed_data[16:])

    code = main(
        [
            "--algorithm", "aes", "--mode", "cfb", "--decrypt",
            "--key", key, "--iv", iv.hex(),
            "--input", str(cipher), "--output", str(result),
        ]
    )

    assert code == 0
    assert result.read_bytes() == data


def test_cli_short_iv_file(tmp_path: Path):  #тест для ошибки при файле без полного iv
    cipher = tmp_path / "cipher.bin"
    result = tmp_path / "result.bin"
    cipher.write_bytes(b"short")

    code = main(
        [
            "--algorithm", "aes", "--mode", "ctr", "--decrypt",
            "--key", "000102030405060708090a0b0c0d0e0f",
            "--input", str(cipher), "--output", str(result),
        ]
    )

    assert code == 1


def test_cli_missing_input(tmp_path: Path):  #тест для ошибки при отсутствующем input
    code = main(
        [
            "--algorithm",
            "aes",
            "--mode",
            "ecb",
            "--encrypt",
            "--key",
            "000102030405060708090a0b0c0d0e0f",
            "--input",
            str(tmp_path / "missing.bin"),
            "--output",
            str(tmp_path / "out.bin"),
        ]
    )

    assert code == 1
