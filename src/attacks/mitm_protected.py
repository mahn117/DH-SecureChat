# src/attacks/mitm_protected.py
from src.crypto.dh import generate_keypair, public_key_bytes, derive_shared_key
from src.crypto.auth import hmac_sign, hmac_verify
from src.crypto.aes import encrypt, decrypt

def authenticated_dh_exchange(psk: bytes):
    # Alice & Bob có PSK chung (giả lập)
    a_priv, a_pub = generate_keypair()
    b_priv, b_pub = generate_keypair()

    # Alice gửi (pub, tag)
    a_pub_bytes = public_key_bytes(a_pub)
    a_tag = hmac_sign(psk, a_pub_bytes)
    if not hmac_verify(psk, a_pub_bytes, a_tag):
        raise RuntimeError("Xác thực public key Alice thất bại")

    # Bob gửi (pub, tag)
    b_pub_bytes = public_key_bytes(b_pub)
    b_tag = hmac_sign(psk, b_pub_bytes)
    if not hmac_verify(psk, b_pub_bytes, b_tag):
        raise RuntimeError("Xác thực public key Bob thất bại")

    a_shared = derive_shared_key(a_priv, b_pub)
    b_shared = derive_shared_key(b_priv, a_pub)
    assert a_shared == b_shared
    return a_shared

def mitm_protected_demo():
    psk = b"demo-psk-very-secret"
    key = authenticated_dh_exchange(psk)

    msg = b"Hello with authenticated DH!"
    payload = encrypt(key, msg)
    out = decrypt(key, payload)
    return out

if __name__ == "__main__":
    print(mitm_protected_demo().decode())
