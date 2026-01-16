# tests/test_dh.py
from src.crypto.dh import generate_keypair, derive_shared_key

def test_dh_shared_key_equal():
    a_priv, a_pub = generate_keypair()
    b_priv, b_pub = generate_keypair()

    a_key = derive_shared_key(a_priv, b_pub)
    b_key = derive_shared_key(b_priv, a_pub)

    assert a_key == b_key
    assert len(a_key) == 32
