# Векторы NIST для хеширования

Неизменённые файлы ShortMsg, LongMsg и Monte для побайтового входа из официальных архивов NIST:

- SHA-256: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip
- SHA3-256: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip

Загружены 20 октября 2026 года. Для Len = 0 значение Msg = 00 обозначает пустое сообщение. Len задан в битах, все выбранные сообщения кратны байту.

| Файл | Число векторов | SHA-256 файла |
| --- | ---: | --- |
| SHA256LongMsg.rsp | 64 | `6fac36f37360bcf74ffcf4465c18e30d6d5a04cc90885b901fc3130c16060974` |
| SHA256ShortMsg.rsp | 65 | `75e1cb83994638481808e225b9eb0c1ebd0c232d952ac42b61abce6363be283c` |
| SHA3_256LongMsg.rsp | 100 | `741b75d093aeb1de3536681b5e7e65090a5eca8015eb75c5f9be0feda47660d5` |
| SHA3_256ShortMsg.rsp | 137 | `e75b1ded16e9862eaaef9ad9b89402b9832f86fe818292634b2e54dc6b3540ff` |
| SHA256Monte.rsp | 100 | `29ea30c6bb4b84e425fb8c1d731c6bb852dac935825f2bd1143e5d3c4f10bfb9` |
| SHA3_256Monte.rsp | 100 | `0b387d75eb7bb96070007ae570601675d4527f50295f41c9d0fbc6c03ec48ca4` |

Запуск из папки `4 спринт`:

```bash
pytest tests/test_nist_hash_vectors.py tests/test_hash_monte.py -q
```

Тесты входят в обычный запуск pytest и работают без сети. Проверяются все записи шести перечисленных файлов. Для каждого алгоритма Monte Carlo выполняет 100 раундов по 1000 хеширований с проверкой всех контрольных значений. Для SHA-256 входом служат три предыдущих хеша, для SHA3-256 — один предыдущий хеш. Битовые наборы не входят в проверку. Реализация принимает байты, поэтому битовые сообщения некратной байту длины не поддерживаются.

Источник и описание: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing

Процедуры Monte Carlo: [SHAVS](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/SHAVS.pdf) и [SHA3VS, раздел 6.2.3](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha3vs.pdf).
