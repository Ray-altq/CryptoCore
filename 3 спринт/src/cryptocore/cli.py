from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptocore.csprng import generate_random_bytes
from cryptocore.file_io import IV_BYTES, add_iv, make_iv, read_binary_file, split_iv, write_binary_file
from cryptocore.modes.cbc import decrypt_cbc, encrypt_cbc
from cryptocore.modes.cfb import decrypt_cfb, encrypt_cfb
from cryptocore.modes.ctr import decrypt_ctr, encrypt_ctr
from cryptocore.modes.ecb import decrypt_ecb, encrypt_ecb
from cryptocore.modes.ofb import decrypt_ofb, encrypt_ofb


AES_128_KEY_BYTES = 16
MODES = ["ecb", "cbc", "cfb", "ofb", "ctr"]


class CliError(Exception):
    """User-facing command-line error."""


@dataclass(frozen=True)
class CliOptions:
    algorithm: str
    mode: str
    encrypt: bool
    decrypt: bool
    key: bytes | None
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
        help="AES-128 key as a 32-character hexadecimal string. Required for decryption.",
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

    #при шифровании ключ можно не передавать, при расшифровании он обязателен
    if args.decrypt and args.key is None:
        raise CliError("--key is required for decryption.")

    key = parse_key(args.key) if args.key is not None else None

    if args.encrypt and iv is not None:
        raise CliError("--iv cannot be used during encryption.")
    if args.mode == "ecb" and iv is not None:
        raise CliError("--iv cannot be used with ECB mode.")

    return CliOptions(
        algorithm=args.algorithm,
        mode=args.mode,
        encrypt=args.encrypt,
        decrypt=args.decrypt,
        key=key,
        iv=iv,
        input_file=Path(args.input_file),
        output_file=Path(args.output_file),
    )


def encrypt_mode(mode: str, data: bytes, key: bytes, iv: bytes) -> bytes:
    #выбираем нужную реализацию режима
    if mode == "cbc":
        return encrypt_cbc(data, key, iv)
    if mode == "cfb":
        return encrypt_cfb(data, key, iv)
    if mode == "ofb":
        return encrypt_ofb(data, key, iv)
    if mode == "ctr":
        return encrypt_ctr(data, key, iv)
    raise CliError(f"unsupported mode: {mode}")


def decrypt_mode(mode: str, data: bytes, key: bytes, iv: bytes) -> bytes:
    if mode == "cbc":
        return decrypt_cbc(data, key, iv)
    if mode == "cfb":
        return decrypt_cfb(data, key, iv)
    if mode == "ofb":
        return decrypt_ofb(data, key, iv)
    if mode == "ctr":
        return decrypt_ctr(data, key, iv)
    raise CliError(f"unsupported mode: {mode}")


def run(options: CliOptions) -> None:
    key = options.key

    #генерируем ключ только для шифрования и выводим его один раз
    if options.encrypt and key is None:
        key = generate_random_bytes(AES_128_KEY_BYTES)
        print(f"[INFO] Generated random key: {key.hex()}")

    if key is None:
        raise CliError("--key is required for decryption.")

    data = read_binary_file(options.input_file)

    #ecb работает по старому формату, без iv в начале файла
    if options.mode == "ecb":
        if options.encrypt:
            result = encrypt_ecb(data, key)
        else:
            result = decrypt_ecb(data, key)
        write_binary_file(options.output_file, result)
        return

    if options.encrypt:
        iv = make_iv()
        encrypted = encrypt_mode(options.mode, data, key, iv)
        result = add_iv(iv, encrypted)
    else:
        #при переданном --iv весь файл считается шифротекстом
        if options.iv is not None:
            iv = options.iv
            encrypted = data
        else:
            iv, encrypted = split_iv(data)
        result = decrypt_mode(options.mode, encrypted, key, iv)

    write_binary_file(options.output_file, result)


def main(argv: list[str] | None = None) -> int:
    try:
        options = parse_options(argv)
        run(options)
    except (CliError, OSError, RuntimeError, ValueError) as exc:
        print(f"cryptocore: error: {exc}", file=sys.stderr)
        return 1

    return 0
