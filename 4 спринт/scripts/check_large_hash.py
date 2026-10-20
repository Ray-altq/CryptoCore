from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic

from cryptocore.hashes.file_hash import CHUNK_SIZE, hash_stream


DEFAULT_SIZE_MB = 1100


def generate_test_file(path: Path, total_bytes: int) -> None:
    chunk = bytes(range(256)) * 32
    written = 0

    #создаем настоящий файл частями, без загрузки всех данных в память
    with path.open("wb") as output_file:
        while written < total_bytes:
            part = chunk[:min(len(chunk), total_bytes - written)]
            output_file.write(part)
            written += len(part)


class CheckedStream:
    def __init__(self, stream, reference, total_bytes: int) -> None:
        self.stream = stream
        self.reference = reference
        self.total_bytes = total_bytes
        self.processed = 0
        self.last_report = monotonic()

    def read(self, size: int) -> bytes:
        if not 0 < size <= CHUNK_SIZE:
            raise ValueError("input must be read in bounded chunks.")

        chunk = self.stream.read(size)
        self.reference.update(chunk)
        self.processed += len(chunk)
        now = monotonic()

        if now - self.last_report >= 10:
            print(f"Processed {self.processed}/{self.total_bytes} bytes", flush=True)
            self.last_report = now

        return chunk


def check_file(path: Path, algorithm: str) -> None:
    reference = hashlib.new(algorithm.replace("-", "_"))
    started = monotonic()

    #эталон получает те же части файла, которые читает hash_stream
    with path.open("rb") as input_file:
        stream = CheckedStream(input_file, reference, path.stat().st_size)
        result = hash_stream(stream, algorithm)

    if stream.processed != stream.total_bytes:
        raise ValueError("not all file bytes were processed.")
    if result != reference.hexdigest():
        raise ValueError(f"{algorithm} does not match hashlib.")

    elapsed = monotonic() - started
    print(f"[OK] {algorithm}: {result} ({elapsed:.2f} seconds)", flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check large-file hashes against hashlib.")
    parser.add_argument("--size-mb", type=int, default=DEFAULT_SIZE_MB, help="File size in decimal MB (default: 1100).")
    parser.add_argument("--algorithm", choices=["sha256", "sha3-256", "all"], default="all")
    args = parser.parse_args(argv)

    if args.size_mb <= 0:
        parser.error("--size-mb must be greater than zero.")

    algorithms = ["sha256", "sha3-256"] if args.algorithm == "all" else [args.algorithm]
    total_bytes = args.size_mb * 1_000_000

    try:
        #временный файл удаляется и при ошибке, и при прерывании Ctrl+C
        with TemporaryDirectory(prefix="cryptocore-hash-") as folder:
            path = Path(folder) / "data.bin"
            generate_test_file(path, total_bytes)
            print(f"Generated {total_bytes} bytes. Checking hashes...", flush=True)
            for algorithm in algorithms:
                check_file(path, algorithm)
    except (OSError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCheck interrupted.", file=sys.stderr)
        return 130

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
