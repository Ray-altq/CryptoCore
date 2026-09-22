from __future__ import annotations

from pathlib import Path


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
