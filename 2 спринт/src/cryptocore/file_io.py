from __future__ import annotations

import os
from pathlib import Path


IV_BYTES = 16


def read_binary_file(path: Path) -> bytes:
    #читаем входной файл только как байты
    try:
        return path.read_bytes()
    except OSError as exc:
        raise OSError(f"failed to read input file '{path}': {exc.strerror}") from exc


def write_binary_file(path: Path, data: bytes) -> None:
    #создаем папки для выходного файла и записываем байты без перекодирования
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    except OSError as exc:
        raise OSError(f"failed to write output file '{path}': {exc.strerror}") from exc


def make_iv() -> bytes:
    #для каждого шифрования создаем новый iv
    return os.urandom(IV_BYTES)


def add_iv(iv: bytes, data: bytes) -> bytes:
    #iv хранится в первых 16 байтах файла
    if len(iv) != IV_BYTES:
        raise ValueError("IV must be exactly 16 bytes.")

    return iv + data


def split_iv(data: bytes) -> tuple[bytes, bytes]:
    if len(data) < IV_BYTES:
        raise ValueError("input file is too short to contain IV.")

    return data[:IV_BYTES], data[IV_BYTES:]
