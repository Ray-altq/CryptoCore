import pytest

from cryptocore.hashes.file_hash import create_hasher


@pytest.mark.parametrize("algorithm", ["sha256", "sha3-256"])
def test_avalanche(algorithm: str):  #тест для изменения одного бита входных данных
    original = b"Hello, world!"
    original_hash = create_hasher(algorithm).update(original).digest()
    differences = []

    #по очереди меняем каждый бит сообщения, чтобы оценить среднее число изменений
    for bit_index in range(len(original) * 8):
        modified = bytearray(original)
        modified[bit_index // 8] ^= 1 << (bit_index % 8)
        modified_hash = create_hasher(algorithm).update(modified).digest()

        changed_bits = sum(
            bin(first ^ second).count("1")
            for first, second in zip(original_hash, modified_hash)
        )
        assert changed_bits > 0
        differences.append(changed_bits)

    average = sum(differences) / len(differences)

    #в среднем должно измениться около половины из 256 бит хеша
    assert 115 < average < 141, f"Average changed bits: {average:.2f}/256"
