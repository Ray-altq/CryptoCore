from pathlib import Path

import pytest

from cryptocore.cli import CliError, main, parse_iv, parse_key, parse_options


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
