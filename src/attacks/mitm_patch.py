# src/attacks/mitm_patch.py
"""
Demo DH + HMAC để chống Man-in-the-Middle (MITM).

Ý tưởng:
- Alice và Bob có sẵn một khóa xác thực chung (pre-shared key) dùng cho HMAC.
- Sau khi trao đổi A, B, cả hai tính:
        MAC = HMAC( auth_key , p || g || A || B )
- Nếu MAC_Alice != MAC_Bob -> ai đó đã can thiệp (MITM) -> hủy kết nối.
"""

from __future__ import annotations

from src.crypto import dh, auth


def _make_handshake_mac(auth_key: bytes, p: int, g: int, A: int, B: int) -> str:
    data = f"{p}|{g}|{A}|{B}".encode("utf-8")
    return auth.make_hmac(auth_key, data)


def run_mitm_protected_demo() -> None:
    # Khóa xác thực dài hạn chia sẻ trước giữa Alice & Bob (ví dụ lưu trong app)
    auth_key = b"demo-pre-shared-auth-key-between-A-and-B"

    p, g = dh.get_parameters()

    print("== Tham số hệ thống ==")
    print(f"p (prime) = {p}")
    print(f"g (base)  = {g}")
    print(f"auth_key (len={len(auth_key)} bytes) dùng cho HMAC.")
    print()

    # ---- Trường hợp 1: Không có MITM, DH + HMAC OK ---- #
    print("=== Trường hợp 1: Kênh sạch, không có MITM ===")
    a = dh.generate_private_exponent(p)
    b = dh.generate_private_exponent(p)

    A = pow(g, a, p)
    B = pow(g, b, p)

    mac_A = _make_handshake_mac(auth_key, p, g, A, B)  # Alice
    mac_B = _make_handshake_mac(auth_key, p, g, A, B)  # Bob

    print(f"Alice tính MAC_A = {mac_A[:32]}...")
    print(f"Bob   tính MAC_B = {mac_B[:32]}...")
    print("So sánh MAC_A và MAC_B...")

    if auth.verify_hmac(auth_key, f"{p}|{g}|{A}|{B}".encode("utf-8"), mac_B):
        print("→ MAC trùng nhau. Không có MITM. Tiếp tục dùng khóa DH.")
    else:
        print("→ MAC KHÔNG trùng (không mong đợi trong kịch bản này).")
    print()

    # ---- Trường hợp 2: Có MITM, Mallory sửa A/B ---- #
    print("=== Trường hợp 2: Mallory can thiệp MITM vào A & B ===")
    a = dh.generate_private_exponent(p)
    b = dh.generate_private_exponent(p)

    A_real = pow(g, a, p)  # Alice tạo
    B_real = pow(g, b, p)  # Bob tạo

    # Mallory sinh hai giá trị giả
    m1 = dh.generate_private_exponent(p)
    m2 = dh.generate_private_exponent(p)
    A_fake = pow(g, m1, p)  # gửi cho Bob thay cho A_real
    B_fake = pow(g, m2, p)  # gửi cho Alice thay cho B_real

    print(f"Alice tạo A_real = {A_real}")
    print(f"Bob   tạo B_real = {B_real}")
    print("Mallory thay thế:")
    print(f"  A_fake gửi cho Bob  = {A_fake}")
    print(f"  B_fake gửi cho Alice= {B_fake}")
    print()

    # Alice nghĩ handshake là (p,g,A_real,B_fake)
    mac_Alice_view = _make_handshake_mac(auth_key, p, g, A_real, B_fake)

    # Bob nghĩ handshake là (p,g,A_fake,B_real)
    mac_Bob_view = _make_handshake_mac(auth_key, p, g, A_fake, B_real)

    print(f"Alice tính MAC theo view của mình   = {mac_Alice_view[:32]}...")
    print(f"Bob   tính MAC theo view của mình    = {mac_Bob_view[:32]}...")
    print("Alice & Bob trao đổi MAC (qua Mallory, nhưng Mallory không sửa được vì không biết auth_key).")
    print("=> So sánh hai MAC:")

    if mac_Alice_view == mac_Bob_view:
        print("  [X] MAC trùng (không mong đợi, nghĩa là bị lộ auth_key).")
    else:
        print("  [✔] MAC KHÔNG trùng -> phát hiện có MITM.")
        print("  => Kết nối bị từ chối, không sử dụng khóa DH này.")
    print()
    print("→ Kết luận: Khi có lớp xác thực HMAC bổ sung cho DH, MITM không thể")
    print("  sửa A/B mà vẫn qua mặt được kiểm tra. Tấn công bị phát hiện.")
    

if __name__ == "__main__":
    run_mitm_protected_demo()
