# CryptoCore

Минималистический криптографический провайдер с консольным интерфейсом.

Во втором спринте поддерживается AES-128 в режимах ECB, CBC, CFB, OFB и CTR. Режимы реализованы поверх блочного примитива AES из `pycryptodome`.

## Зависимости

- Python 3.10+
- pycryptodome
- pytest
- OpenSSL для дополнительной проверки совместимости

## Установка

Команды нужно выполнять из папки `2 спринт`.

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

Шифрование в режиме CBC:

```powershell
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

Расшифрование в режиме CBC:

```powershell
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

Вместо `cbc` можно передать `ecb`, `cfb`, `ofb` или `ctr`. Ключ передаётся как hex-строка длиной 32 символа, то есть 16 байт AES-128.

Для CBC, CFB, OFB и CTR при шифровании создаётся случайный IV длиной 16 байт. Выходной файл имеет формат:

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

Тест совместимости запускается автоматически, если команда `openssl` доступна в `PATH`. Без OpenSSL эти четыре проверки будут пропущены.

## Структура

```text
2 спринт/
├── src/
│   └── cryptocore/
│       ├── cli.py
│       ├── file_io.py
│       └── modes/
│           ├── ecb.py
│           ├── cbc.py
│           ├── cfb.py
│           ├── ofb.py
│           └── ctr.py
├── tests/
├── pyproject.toml
├── requirements.txt
└── README.md
```
