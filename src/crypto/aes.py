# src/crypto/aes.py
from __future__ import annotations

import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


def _get_cipher(key: bytes, iv: bytes) -> Cipher:
    return Cipher(algorithms.AES(key), modes.CBC(iv))


def encrypt_message(key: bytes, plaintext: str) -> str:
    """
    Mã hóa chuỗi plaintext bằng AES-256-CBC, trả về base64(iv || ciphertext).
    """
    if len(key) != 32:
        raise ValueError("Key AES phải có độ dài 32 byte (AES-256).")

    iv = os.urandom(16)
    cipher = _get_cipher(key, iv)
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()

    ciphertext = encryptor.update(padded) + encryptor.finalize()
    data = iv + ciphertext
    return base64.b64encode(data).decode("ascii")


def decrypt_message(key: bytes, token: str) -> str:
    """
    Giải mã chuỗi base64(iv || ciphertext) → plaintext.
    """
    if len(key) != 32:
        raise ValueError("Key AES phải có độ dài 32 byte (AES-256).")

    raw = base64.b64decode(token)
    iv, ciphertext = raw[:16], raw[16:]

    cipher = _get_cipher(key, iv)
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded) + unpadder.finalize()
    return data.decode("utf-8")
