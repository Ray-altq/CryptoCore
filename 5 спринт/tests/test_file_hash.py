import hashlib
import io
from pathlib import Path

import pytest

from cryptocore.hashes.file_hash import CHUNK_SIZE, hash_file, hash_stream


@pytest.mark.parametrize("algorithm", ["sha256", "sha3-256"])
@pytest.mark.parametrize("size", [0, 8191, 8192, 8193, 24593])
def test_file_hash(algorithm: str, size: int, tmp_path: Path):  #тест для файлов разного размера
    data = bytes((index * 19) % 256 for index in range(size))
    source = tmp_path / "data.bin"
    source.write_bytes(data)

    expected = hashlib.new(algorithm.replace("-", "_"), data).hexdigest()

    assert hash_file(source, algorithm) == expected


@pytest.mark.parametrize("algorithm", ["sha256", "sha3-256"])
def test_stream_chunks(algorithm: str):  #тест для чтения потока ограниченными частями
    data = bytes(range(256)) * 97 + b"last bytes"

    class ChunkedStream(io.BytesIO):
        def read(self, size: int = -1) -> bytes:
            assert 0 < size <= CHUNK_SIZE
            #поток может вернуть меньше байтов, чем было запрошено
            return super().read(min(size, 137))

    stream = ChunkedStream(data)
    expected = hashlib.new(algorithm.replace("-", "_"), data).hexdigest()

    assert hash_stream(stream, algorithm) == expected
    assert not stream.closed


@pytest.mark.parametrize("algorithm", ["sha256", "sha3-256"])
def test_missing_file(algorithm: str, tmp_path: Path):  #тест для отсутствующего входного файла
    source = tmp_path / "missing.bin"

    with pytest.raises(OSError, match="input file not found"):
        hash_file(source, algorithm)


def test_bad_algorithm():  #тест для неподдерживаемого алгоритма
    with pytest.raises(ValueError, match="unsupported hash algorithm"):
        hash_stream(io.BytesIO(b"abc"), "md5")
