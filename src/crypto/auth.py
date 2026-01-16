# src/crypto/auth.py
from __future__ import annotations

import hmac
import hashlib
from typing import Tuple


def make_hmac(key: bytes, data: bytes) -> str:
    """
    Tạo HMAC-SHA256(key, data), trả về chuỗi hex.
    """
    mac = hmac.new(key, data, hashlib.sha256).hexdigest()
    return mac


def verify_hmac(key: bytes, data: bytes, mac_hex: str) -> bool:
    """
    Kiểm tra HMAC-SHA256(key, data) có trùng với mac_hex không.
    """
    mac_calc = make_hmac(key, data)
    return hmac.compare_digest(mac_calc, mac_hex)
