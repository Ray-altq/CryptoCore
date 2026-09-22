from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptocore.file_io import read_binary_file, write_binary_file
from cryptocore.modes.ecb import decrypt_ecb, encrypt_ecb


AES_128_KEY_BYTES = 16
IV_BYTES = 16
MODES = ["ecb", "cbc", "cfb", "ofb", "ctr"]


class CliError(Exception):
    """User-facing command-line error."""


@dataclass(frozen=True)
class CliOptions:
    algorithm: str
    mode: str
    encrypt: bool
    decrypt: bool
    key: bytes
    iv: bytes | None
    input_file: Path
    output_file: Path


def build_parser() -> argparse.ArgumentParser:
    #основной набор аргументов для второго спринта
    parser = argparse.ArgumentParser(
        prog="cryptocore",
        description="Minimalist cryptographic CLI provider.",
    )
    parser.add_argument(
        "--algorithm",
        required=True,
        choices=["aes"],
        help="Cipher algorithm. Sprint 1 supports only 'aes'.",
    )
    parser.add_argument(
        "--mode",
        required=True,
        choices=MODES,
        help="Cipher mode: ecb, cbc, cfb, ofb, ctr.",
    )

    #операция должна быть выбрана ровно одна
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--encrypt", action="store_true", help="Encrypt the input file.")
    operation.add_argument("--decrypt", action="store_true", help="Decrypt the input file.")

    parser.add_argument(
        "--key",
        required=True,
        help="AES-128 key as a 32-character hexadecimal string.",
    )
    parser.add_argument("--iv", help="IV as a 32-character hexadecimal string for decryption.")
    parser.add_argument("--input", required=True, dest="input_file", help="Input file path.")
    parser.add_argument("--output", required=True, dest="output_file", help="Output file path.")
    return parser


def parse_key(hex_key: str) -> bytes:
    #ключ принимается как hex-строка и превращается в байты
    try:
        key = bytes.fromhex(hex_key)
    except ValueError as exc:
        raise CliError("--key must be a valid hexadecimal string.") from exc

    if len(key) != AES_128_KEY_BYTES:
        raise CliError("--key must encode exactly 16 bytes for AES-128.")

    return key


def parse_iv(hex_iv: str | None) -> bytes | None:
    if hex_iv is None:
        return None

    #iv тоже приходит в hex, как и ключ
    try:
        iv = bytes.fromhex(hex_iv)
    except ValueError as exc:
        raise CliError("--iv must be a valid hexadecimal string.") from exc

    if len(iv) != IV_BYTES:
        raise CliError("--iv must encode exactly 16 bytes.")

    return iv


def parse_options(argv: list[str] | None = None) -> CliOptions:
    args = build_parser().parse_args(argv)
    iv = parse_iv(args.iv)

    if args.encrypt and iv is not None:
        raise CliError("--iv cannot be used during encryption.")

    return CliOptions(
        algorithm=args.algorithm,
        mode=args.mode,
        encrypt=args.encrypt,
        decrypt=args.decrypt,
        key=parse_key(args.key),
        iv=iv,
        input_file=Path(args.input_file),
        output_file=Path(args.output_file),
    )


def run(options: CliOptions) -> None:
    #тут уже собираем вместе cli, файлы и ecb
    data = read_binary_file(options.input_file)

    if options.encrypt:
        result = encrypt_ecb(data, options.key)
    else:
        result = decrypt_ecb(data, options.key)

    write_binary_file(options.output_file, result)


def main(argv: list[str] | None = None) -> int:
    try:
        options = parse_options(argv)
        run(options)
    except (CliError, OSError, ValueError) as exc:
        print(f"cryptocore: error: {exc}", file=sys.stderr)
        return 1

    return 0
