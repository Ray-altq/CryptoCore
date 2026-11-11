# CryptoCore

Минималистический криптографический провайдер с консольным интерфейсом.

Пятый спринт подготовлен на основе четвёртого: сохранены AES-128 в режимах ECB, CBC, CFB, OFB и CTR, SHA-256, SHA3-256 и генерация ключей и IV через системный CSPRNG. Добавлена собственная реализация HMAC-SHA256 на основе SHA-256 и поддержка HMAC в команде `dgst`.

## Зависимости

- Python 3.10+
- pycryptodome
- pytest
- OpenSSL для дополнительной проверки совместимости
- NIST Statistical Test Suite для статистической проверки случайных данных

## Установка

Команды нужно выполнять из папки `5 спринт`.

Для Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Для Linux и macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

Если нужна только основная зависимость без установки пакета:

```powershell
python -m pip install -r requirements.txt
```

## Использование

Ключ при шифровании можно не указывать:

```powershell
cryptocore --algorithm aes --mode ctr --encrypt --input plaintext.txt --output ciphertext.bin
```

Программа создаст случайный ключ длиной 16 байт и один раз напечатает его в стандартный вывод:

```text
[INFO] Generated random key: 52c4c8e92ee9f8667b5e1d187ffb881a
```

Ключ нужно сохранить для последующего расшифрования. В выходной файл он не записывается. При расшифровании параметр `--key` обязателен:

```powershell
cryptocore --algorithm aes --mode ctr --decrypt --key 52c4c8e92ee9f8667b5e1d187ffb881a --input ciphertext.bin --output decrypted.txt
```

Свой ключ можно передать и при шифровании:

```powershell
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

Вместо `cbc` можно передать `ecb`, `cfb`, `ofb` или `ctr`. Ключ задаётся hex-строкой длиной 32 символа, то есть 16 байт AES-128.

Если пользователь передал явно слабый ключ, например нулевой или последовательный, программа выведет предупреждение в `stderr`, но не прервёт работу:

```text
[WARNING] Weak key detected.
```

## Генерация случайных данных

Функция `generate_random_bytes()` находится в отдельном модуле `csprng.py` и использует `os.urandom`. Обычный модуль `random` для криптографических данных не используется.

Системный CSPRNG применяется для автоматически созданных ключей и всех IV. Для CBC, CFB, OFB и CTR при шифровании создаётся IV длиной 16 байт. Формат выходного файла не изменился:

```text
<16 байт IV><шифротекст>
```

При расшифровании IV читается из начала файла. Если шифротекст хранится отдельно, IV можно передать явно:

```powershell
cryptocore --algorithm aes --mode ctr --decrypt --key 000102030405060708090a0b0c0d0e0f --iv 101112131415161718191a1b1c1d1e1f --input cipher.raw --output decrypted.txt
```

Параметр `--iv` нельзя использовать при шифровании и в режиме ECB.

## Дополнение данных

CBC использует PKCS#7. В CFB используется полный сегмент 128 бит. CFB, OFB и CTR работают без padding и сохраняют исходную длину данных.

## Совместимость с OpenSSL

Чтобы расшифровать файл CryptoCore через OpenSSL, сначала отделите IV от шифротекста:

```powershell
$data = [IO.File]::ReadAllBytes("ciphertext.bin")
$iv = ($data[0..15] | ForEach-Object { $_.ToString("x2") }) -join ""
[IO.File]::WriteAllBytes("cipher.raw", $data[16..($data.Length - 1)])
```

Затем выберите ту же команду режима:

```powershell
openssl enc -d -aes-128-cbc -K 000102030405060708090a0b0c0d0e0f -iv $iv -nosalt -in cipher.raw -out openssl-result.txt
openssl enc -d -aes-128-cfb -K 000102030405060708090a0b0c0d0e0f -iv $iv -nosalt -in cipher.raw -out openssl-result.txt
openssl enc -d -aes-128-ofb -K 000102030405060708090a0b0c0d0e0f -iv $iv -nosalt -in cipher.raw -out openssl-result.txt
openssl enc -d -aes-128-ctr -K 000102030405060708090a0b0c0d0e0f -iv $iv -nosalt -in cipher.raw -out openssl-result.txt
```

Для проверки в обратную сторону сначала зашифруйте файл в OpenSSL, затем передайте тот же IV в CryptoCore:

```powershell
$iv = "101112131415161718191a1b1c1d1e1f"
openssl enc -aes-128-ctr -K 000102030405060708090a0b0c0d0e0f -iv $iv -nosalt -in plaintext.txt -out openssl.bin
cryptocore --algorithm aes --mode ctr --decrypt --key 000102030405060708090a0b0c0d0e0f --iv $iv --input openssl.bin --output result.txt
```

## Вычисление хешей

Для хеширования используется отдельная команда `dgst`. Поддерживаются алгоритмы `sha256` и `sha3-256`:

```powershell
cryptocore dgst --algorithm sha256 --input plaintext.txt
cryptocore dgst --algorithm sha3-256 --input plaintext.txt
```

Результат выводится в формате `хеш  путь_к_файлу`. Хеш записывается строчными шестнадцатеричными символами. Чтобы сохранить результат в файл, передайте `--output`:

```powershell
cryptocore dgst --algorithm sha3-256 --input plaintext.txt --output plaintext.sha3
```

Вместо пути можно указать `-` для чтения из стандартного ввода. Например, в Linux и macOS:

```bash
printf 'abc' | cryptocore dgst --algorithm sha256 --input -
```

SHA-256 использует блоки по 64 байта, SHA3-256 основан на конструкции губки Keccak с блоками поглощения по 136 байт. Оба алгоритма формируют хеш длиной 256 бит. Файлы читаются в бинарном режиме частями по 8192 байта, поэтому при хешировании не требуется загружать файл целиком в память.

Хеш позволяет обнаружить изменение данных при сравнении с доверенным значением. Без секретного ключа он не подтверждает подлинность отправителя. Параметры шифрования `--mode`, `--iv`, `--encrypt` и `--decrypt` для `dgst` не принимаются. Параметр `--key` используется только вместе с `--hmac`.

Для проверки результата SHA-256 в Linux:

```bash
cryptocore dgst --algorithm sha256 --input plaintext.txt > computed.sha256
sha256sum plaintext.txt > expected.sha256
diff computed.sha256 expected.sha256
```

Хеш SHA3-256 можно сравнить со значением OpenSSL:

```bash
cryptocore dgst --algorithm sha3-256 --input plaintext.txt
openssl dgst -sha3-256 plaintext.txt
```

Формат вывода OpenSSL отличается, поэтому сравнивать нужно сами значения хешей.

## HMAC-SHA256

HMAC использует секретный ключ и хеширование для проверки целостности и подлинности сообщения. Он не шифрует данные. Реализация находится в `mac/hmac.py` и использует собственный SHA-256 проекта, без библиотечной реализации HMAC. Файлы читаются частями через `mac/file_mac.py`, поэтому большой файл не загружается в память целиком.

Конструкция следует RFC 2104: `HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))`, где `ipad` — повторяющийся байт `0x36`, `opad` — повторяющийся байт `0x5c`, а `H` — SHA-256. Ключ длиннее 64 байт сначала хешируется, более короткий дополняется нулями. HMAC подтверждает целостность и знание ключа, но не скрывает содержимое сообщения.

Ключ передаётся в `--key` как hex-строка произвольной длины. HMAC в этой версии работает только с `sha256`.

Создание HMAC и вывод в консоль:

```powershell
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt
```

Результат выводится в формате `значение_hmac  путь_к_файлу`:

```text
a1b2c3d4e5f6012345678901234567890123456789012345678901234567890123  message.txt
```

Чтобы сохранить значение в файл, добавьте `--output`:

```powershell
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt --output message.hmac
```

Проверка сохранённого HMAC:

```powershell
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt --verify message.hmac
```

При совпадении выводится `[OK] HMAC verification successful` и код возврата 0. Если файл или ключ изменились, выводится `[ERROR] HMAC verification failed`, код возврата 1, а новый файл не создаётся. Значение в файле можно хранить как отдельный hex, так и в формате `значение  имя_файла`; регистр hex-символов и лишние пробелы не важны. Сравнение выполняется через `hmac.compare_digest`, чтобы не раскрывать время совпадения посимвольно. Параметры `--verify` и `--output` вместе не используются.

Данные можно читать из стандартного ввода:

```bash
printf 'abc' | cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input -
```

HMAC также доступен через Python API:

```python
from cryptocore.mac import HMAC, hmac_sha256

key = bytes.fromhex("00112233445566778899aabbccddeeff")
value = hmac_sha256(key, b"message")

mac = HMAC(key)
mac.update(b"mes")
mac.update(b"sage")
assert mac.hexdigest() == value
```

Ключи длиннее 64 байт сначала хешируются, короткие дополняются нулями. `digest()` возвращает 32 байта, `hexdigest()` — 64 строчных hex-символа. Повторное получение результата не мешает дальнейшему `update()`. Для практического использования выбирайте случайный секретный ключ достаточной длины; возможность обработать пустой ключ нужна для корректности API, но не является рекомендацией.

## Тесты

```powershell
pytest
```

Тесты проверяют все режимы AES, совместимость с OpenSSL, уникальность 1000 ключей и распределение нулевых и единичных битов. Для SHA-256 и SHA3-256 проверяются известные векторы, пустые данные, миллион символов `a` и обновление хеша частями. Отдельные тесты проверяют команду `dgst`, чтение из stdin и запись результата в файл. Для HMAC дополнительно проверяются векторы RFC 4231, ключи разной длины, пустой файл, чтение потока частями, успешная проверка `--verify`, изменение файла, неверный ключ и повреждённый файл с ожидаемым значением. Для отдельной проверки файла больше 1 ГБ добавлены скрипты `scripts/check_large_hash.py` и `scripts/check_large_hmac.py`; команды запуска описаны в `TESTING.md`. Статистические проверки дополняют использование системного CSPRNG, но сами по себе не доказывают криптографическую стойкость.

Тесты совместимости запускаются автоматически, если команда `openssl` доступна в `PATH`. Без OpenSSL эти восемь проверок будут пропущены.

Для подготовки бинарного файла объёмом 10 МБ для NIST STS:

```powershell
python scripts/generate_nist_data.py --size-mb 10 --output nist_random.bin
```

Все 15 тестов NIST STS были запущены на 80 последовательностях по 1 000 000 бит. Пропорции прошли допустимые границы, а три значения равномерности P-value оказались ниже `0.01`. Точная процедура и разбор результатов находятся в `TESTING.md`, полный отчёт сохранён в `nist_results/finalAnalysisReport.txt`.

## Структура

```text
5 спринт/
├── scripts/
│   ├── generate_nist_data.py
│   ├── check_large_hash.py
│   └── check_large_hmac.py
├── src/
│   └── cryptocore/
│       ├── cli.py
│       ├── csprng.py
│       ├── file_io.py
│       ├── mac/
│       │   ├── __init__.py
│       │   ├── file_mac.py
│       │   └── hmac.py
│       ├── hashes/
│       │   ├── file_hash.py
│       │   ├── sha256.py
│       │   └── sha3_256.py
│       └── modes/
│           ├── ecb.py
│           ├── cbc.py
│           ├── cfb.py
│           ├── ofb.py
│           └── ctr.py
├── nist_results/
│   └── finalAnalysisReport.txt
├── tests/
├── TESTING.md
├── pyproject.toml
├── requirements.txt
└── README.md
```
