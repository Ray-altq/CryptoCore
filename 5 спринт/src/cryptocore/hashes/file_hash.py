from __future__ import annotations

from pathlib import Path
from typing import BinaryIO

from cryptocore.hashes.sha256 import SHA256
from cryptocore.hashes.sha3_256 import SHA3_256


CHUNK_SIZE = 8192


def create_hasher(algorithm: str) -> SHA256 | SHA3_256:
    if algorithm == "sha256":
        return SHA256()
    if algorithm == "sha3-256":
        return SHA3_256()
    raise ValueError(f"unsupported hash algorithm: {algorithm}")


def hash_stream(stream: BinaryIO, algorithm: str) -> str:
    hasher = create_hasher(algorithm)

    #файл читается небольшими частями и целиком в память не попадает
    while True:
        chunk = stream.read(CHUNK_SIZE)
        if not chunk:
            break
        hasher.update(chunk)

    return hasher.hexdigest()


def hash_file(path: Path, algorithm: str) -> str:
    try:
        with path.open("rb") as input_file:
            return hash_stream(input_file, algorithm)
    except FileNotFoundError as exc:
        raise OSError(f"input file not found: {path}") from exc
