# src/crypto/dh.py
from __future__ import annotations

import hashlib

# Để đơn giản và an toàn, dùng nhóm MODP 2048-bit từ RFC 3526 (group 14)
# Ở quy mô đồ án là quá đủ. g = 2, p là số nguyên tố lớn.
P_HEX = """
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024
E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3C
020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B
0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9
A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B
1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A
69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED5
290770E5E8B06B5A0F1C9D8A3E5A8A1FC09C3C1B
""".replace("\n", "").replace(" ", "")

P = int(P_HEX, 16)
G = 2


def get_parameters() -> tuple[int, int]:
    """Trả về (p, g) dùng chung cho toàn hệ thống."""
    return P, G


def generate_private_exponent(p: int) -> int:
    """
    Sinh số bí mật a hoặc b.
    2 ≤ exponent ≤ p-2.
    """
    import secrets

    return secrets.randbelow(p - 3) + 2


def generate_keypair(
    p: int | None = None,
    g: int | None = None,
    exponent: int | None = None,
) -> dict:
    """
    Sinh cặp khóa Diffie–Hellman.

    - Nếu p,g None -> lấy tham số mặc định (P,G).
    - Nếu exponent None -> sinh ngẫu nhiên.
    """
    if p is None or g is None:
        p, g = get_parameters()

    if exponent is None:
        exponent = generate_private_exponent(p)

    public = pow(g, exponent, p)

    return {
        "p": p,
        "g": g,
        "private": exponent,
        "public": public,
    }


def compute_shared_secret(
    their_public: int,
    my_private: int,
    p: int,
) -> int:
    """
    Tính s = (their_public)^(my_private) mod p.
    """
    return pow(their_public, my_private, p)


def derive_key_from_secret(secret: int) -> bytes:
    """
    Từ secret (số nguyên) → key AES-256 (32 byte) bằng SHA-256.
    """
    s_bytes = str(secret).encode("utf-8")
    return hashlib.sha256(s_bytes).digest()


def compute_shared_key(
    their_public: int,
    my_private: int,
    p: int,
) -> tuple[bytes, int]:
    """
    Tính shared_key (32 byte) và secret (int) từ public của peer và private của mình.
    """
    secret = compute_shared_secret(their_public, my_private, p)
    key = derive_key_from_secret(secret)
    return key, secret


def preview_from_key(key: bytes) -> str:
    """
    Chuỗi hex rút gọn để hiển thị trên GUI.
    """
    return key.hex()[:16]
