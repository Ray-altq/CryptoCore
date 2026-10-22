from pathlib import Path

import pytest

from cryptocore.hashes.file_hash import create_hasher


VECTORS = Path(__file__).parent / "vectors"


def load_vectors(filename: str):
    case = {}

    for line in (VECTORS / filename).read_text(encoding="ascii").splitlines():
        if " = " not in line or line.startswith(("#", "[")):
            continue
        name, value = line.split(" = ", 1)
        case[name] = value

        if name == "MD":
            length = int(case["Len"])
            assert length % 8 == 0
            #при Len = 0 в файле указан Msg = 00, но сообщение пустое
            data = bytes.fromhex(case["Msg"]) if length else b""
            assert len(data) * 8 == length
            yield pytest.param(data, case["MD"], id=f"{filename}-{length}")
            case = {}


@pytest.mark.parametrize("data, expected", list(load_vectors("SHA256ShortMsg.rsp")) + list(load_vectors("SHA256LongMsg.rsp")))
def test_sha256_nist(data: bytes, expected: str):  #тест для официальных коротких и длинных сообщений NIST
    assert create_hasher("sha256").update(data).hexdigest() == expected


@pytest.mark.parametrize("data, expected", list(load_vectors("SHA3_256ShortMsg.rsp")) + list(load_vectors("SHA3_256LongMsg.rsp")))
def test_sha3_nist(data: bytes, expected: str):  #тест для официальных коротких и длинных сообщений NIST
    assert create_hasher("sha3-256").update(data).hexdigest() == expected
