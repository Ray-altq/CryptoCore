# Векторы NIST для хеширования

Неизменённые файлы ShortMsg и LongMsg для побайтового входа из официальных архивов NIST:

- SHA-256: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip
- SHA3-256: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip

Загружены 20 октября 2026 года. Для Len = 0 значение Msg = 00 обозначает пустое сообщение. Len задан в битах, все выбранные сообщения кратны байту.

| Файл | Число векторов | SHA-256 файла |
| --- | ---: | --- |
| SHA256LongMsg.rsp | 64 | `6fac36f37360bcf74ffcf4465c18e30d6d5a04cc90885b901fc3130c16060974` |
| SHA256ShortMsg.rsp | 65 | `75e1cb83994638481808e225b9eb0c1ebd0c232d952ac42b61abce6363be283c` |
| SHA3_256LongMsg.rsp | 100 | `741b75d093aeb1de3536681b5e7e65090a5eca8015eb75c5f9be0feda47660d5` |
| SHA3_256ShortMsg.rsp | 137 | `e75b1ded16e9862eaaef9ad9b89402b9832f86fe818292634b2e54dc6b3540ff` |

Запуск из папки `4 спринт`:

```bash
pytest tests/test_nist_hash_vectors.py -q
```

Тесты входят в обычный запуск pytest и работают без сети. Проверяются все записи четырёх перечисленных файлов. Monte Carlo и битовые наборы в этот блок не входят. Реализация принимает байты, поэтому битовые сообщения некратной байту длины не поддерживаются.

Источник и описание: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing
