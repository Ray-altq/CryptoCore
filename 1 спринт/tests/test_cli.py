from pathlib import Path

import pytest

from cryptocore.cli import CliError, parse_key, parse_options


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
