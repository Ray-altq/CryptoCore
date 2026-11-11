from __future__ import annotations

import hmac

from pathlib import Path
from typing import BinaryIO

from cryptocore.mac.hmac import HMAC


CHUNK_SIZE = 8192


def hmac_stream(stream: BinaryIO, key: bytes) -> str:
    mac = HMAC(key)

    #файл читается небольшими частями и целиком в память не попадает
    while True:
        chunk = stream.read(CHUNK_SIZE)
        if not chunk:
            break
        mac.update(chunk)

    return mac.hexdigest()


def hmac_file(path: Path, key: bytes) -> str:
    try:
        with path.open("rb") as input_file:
            return hmac_stream(input_file, key)
    except FileNotFoundError as exc:
        raise OSError(f"input file not found: {path}") from exc


def read_expected_hmac(path: Path) -> str:
    #в файле может быть только значение или строка формата "значение  имя_файла"
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise OSError(f"failed to read HMAC file '{path}': {exc.strerror}") from exc

    fields = content.split()
    if not fields:
        raise ValueError(f"HMAC file '{path}' is empty.")

    return fields[0]


def verify_hmac(expected: str, actual: str) -> bool:
    #сравниваем байты и валидируем hex, чтобы не принимать мусор за совпадение
    try:
        expected_bytes = bytes.fromhex(expected)
        actual_bytes = bytes.fromhex(actual)
    except ValueError:
        return False

    return hmac.compare_digest(expected_bytes, actual_bytes)
