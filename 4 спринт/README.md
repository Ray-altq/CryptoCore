# CryptoCore

Минималистический криптографический провайдер с консольным интерфейсом.

В третьем спринте поддерживается AES-128 в режимах ECB, CBC, CFB, OFB и CTR. Добавлена безопасная генерация ключей и IV через системный CSPRNG.

## Зависимости

- Python 3.10+
- pycryptodome
- pytest
- OpenSSL для дополнительной проверки совместимости
- NIST Statistical Test Suite для статистической проверки случайных данных

## Установка

Команды нужно выполнять из папки `3 спринт`.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
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

## Тесты

```powershell
pytest
```

Тесты проверяют все режимы AES, совместимость с OpenSSL, уникальность 1000 ключей и распределение нулевых и единичных битов. Статистические проверки дополняют использование системного CSPRNG, но сами по себе не доказывают криптографическую стойкость.

Тесты совместимости запускаются автоматически, если команда `openssl` доступна в `PATH`. Без OpenSSL эти восемь проверок будут пропущены.

Для подготовки бинарного файла объёмом 10 МБ для NIST STS:

```powershell
python scripts/generate_nist_data.py --size-mb 10 --output nist_random.bin
```

Все 15 тестов NIST STS были запущены на 80 последовательностях по 1 000 000 бит. Пропорции прошли допустимые границы, а три значения равномерности P-value оказались ниже `0.01`. Точная процедура и разбор результатов находятся в `TESTING.md`, полный отчёт сохранён в `nist_results/finalAnalysisReport.txt`.

## Структура

```text
3 спринт/
├── scripts/
│   └── generate_nist_data.py
├── src/
│   └── cryptocore/
│       ├── cli.py
│       ├── csprng.py
│       ├── file_io.py
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
