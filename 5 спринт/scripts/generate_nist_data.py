from __future__ import annotations

import argparse
from pathlib import Path

from cryptocore.csprng import generate_random_bytes


DEFAULT_SIZE_MB = 10
CHUNK_BYTES = 4096


def generate_test_file(path: Path, total_bytes: int) -> int:
    if total_bytes <= 0:
        raise ValueError("test file size must be greater than zero.")

    path.parent.mkdir(parents=True, exist_ok=True)
    written = 0

    #пишем небольшими частями, чтобы не держать весь файл в памяти
    with path.open("wb") as output_file:
        while written < total_bytes:
            chunk_size = min(CHUNK_BYTES, total_bytes - written)
            output_file.write(generate_random_bytes(chunk_size))
            written += chunk_size

    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate binary data for NIST STS.")
    parser.add_argument("--output", default="nist_random.bin", help="Output binary file.")
    parser.add_argument("--size-mb", type=int, default=DEFAULT_SIZE_MB, help="File size in MB.")
    args = parser.parse_args(argv)

    #десятичные мегабайты удобно делятся на потоки по миллиону бит
    total_bytes = args.size_mb * 1_000_000
    written = generate_test_file(Path(args.output), total_bytes)
    print(f"Generated {written} bytes in '{args.output}'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
