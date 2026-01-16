# tests/test_aes.py
from src.crypto.aes import encrypt, decrypt

def test_aes_encrypt_decrypt_roundtrip():
    key = b"\x01" * 32
    plaintext = b"hello aes-gcm"
    payload = encrypt(key, plaintext, aad=b"meta")
    out = decrypt(key, payload)
    assert out == plaintext
