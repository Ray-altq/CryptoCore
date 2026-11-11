from __future__ import annotations

import os


def generate_random_bytes(num_bytes: int) -> bytes:
    #размер не может быть отрицательным
    if num_bytes < 0:
        raise ValueError("number of random bytes cannot be negative.")

    #используем безопасный генератор операционной системы
    try:
        return os.urandom(num_bytes)
    except (OSError, NotImplementedError) as exc:
        raise RuntimeError("failed to get secure random bytes from the operating system.") from exc
