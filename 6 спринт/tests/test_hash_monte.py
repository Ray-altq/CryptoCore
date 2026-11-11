from pathlib import Path

from cryptocore.hashes.file_hash import create_hasher


VECTORS = Path(__file__).parent / "vectors"


def load_monte(filename: str):
    seed = None
    expected = []

    for line in (VECTORS / filename).read_text(encoding="ascii").splitlines():
        if line.startswith("Seed = "):
            seed = bytes.fromhex(line.split(" = ")[1])
        elif line.startswith("COUNT = "):
            assert int(line.split(" = ")[1]) == len(expected)
        elif line.startswith("MD = "):
            expected.append(bytes.fromhex(line.split(" = ")[1]))

    assert seed is not None and len(seed) == 32
    assert len(expected) == 100
    assert all(len(value) == 32 for value in expected)
    return seed, expected


def test_sha256_monte():  #тест для всех 100 контрольных значений SHA-256 Monte Carlo
    seed, expected = load_monte("SHA256Monte.rsp")

    for count, digest in enumerate(expected):
        first = second = third = seed
        for _ in range(1000):
            result = create_hasher("sha256").update(first + second + third).digest()
            first, second, third = second, third, result
        assert third == digest, f"SHA-256 Monte Carlo COUNT = {count}"
        seed = third


def test_sha3_monte():  #тест для всех 100 контрольных значений SHA3-256 Monte Carlo
    seed, expected = load_monte("SHA3_256Monte.rsp")

    for count, digest in enumerate(expected):
        for _ in range(1000):
            seed = create_hasher("sha3-256").update(seed).digest()
        assert seed == digest, f"SHA3-256 Monte Carlo COUNT = {count}"
