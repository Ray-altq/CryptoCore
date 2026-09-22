from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path


AES_128_KEY_BYTES = 16


class CliError(Exception):
    """User-facing command-line error."""


@dataclass(frozen=True)
class CliOptions:
    algorithm: str
    mode: str
    encrypt: bool
    decrypt: bool
    key: bytes
    input_file: Path
    output_file: Path


def build_parser() -> argparse.ArgumentParser:
    #основной набор аргументов для первого спринта
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
        choices=["ecb"],
        help="Cipher mode. Sprint 1 supports only 'ecb'.",
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


def parse_options(argv: list[str] | None = None) -> CliOptions:
    args = build_parser().parse_args(argv)
    return CliOptions(
        algorithm=args.algorithm,
        mode=args.mode,
        encrypt=args.encrypt,
        decrypt=args.decrypt,
        key=parse_key(args.key),
        input_file=Path(args.input_file),
        output_file=Path(args.output_file),
    )


def run(options: CliOptions) -> None:
    #реальная обработка файлов и криптография будут добавлены следующими блоками
    raise CliError("encryption and decryption are not implemented yet.")


def main(argv: list[str] | None = None) -> int:
    try:
        options = parse_options(argv)
        run(options)
    except CliError as exc:
        print(f"cryptocore: error: {exc}", file=sys.stderr)
        return 1

    return 0
