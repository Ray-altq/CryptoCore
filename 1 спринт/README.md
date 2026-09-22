# CryptoCore

Минималистический криптографический провайдер с консольным интерфейсом.

В первом спринте проект должен реализовать базовое шифрование и расшифрование AES-128 в режиме ECB с дополнением PKCS#7.

## Зависимости

- Python 3.10+
- pycryptodome
- pytest

## Установка

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

## Планируемое использование

```powershell
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
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
