# CryptoCore

Минималистический криптографический провайдер с консольным интерфейсом.

В первом спринте реализованы шифрование и расшифрование AES-128 в режиме ECB с дополнением PKCS#7.

## Зависимости

- Python 3.10+
- pycryptodome
- pytest

## Установка

Команды нужно выполнять из папки `1 спринт`.

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

```powershell
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

`--key` передается как hex-строка длиной 32 символа. Это 16 байт, то есть ключ AES-128.

## Проверка полного цикла

```powershell
"hello cryptocore" | Out-File -Encoding ascii plaintext.txt
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
fc plaintext.txt decrypted.txt
```

Если расшифрование прошло правильно, `fc` не должен показать различий.

## Тесты

```powershell
pytest
```

## Структура

```text
1 спринт/
├── src/
│   └── cryptocore/
│       ├── cli.py
│       ├── file_io.py
│       └── modes/
│           └── ecb.py
├── tests/
├── pyproject.toml
├── requirements.txt
└── README.md
```
