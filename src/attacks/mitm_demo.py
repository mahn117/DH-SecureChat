# src/attacks/mitm_demo.py
"""
Demo tấn công Man-in-the-Middle (MITM) trên Diffie–Hellman thuần.

Mô hình:
    Alice  <-->  Mallory  <-->  Bob

- Alice nghĩ đang nói chuyện trực tiếp với Bob.
- Bob cũng nghĩ đang nói chuyện trực tiếp với Alice.
- Thực tế:
    + Alice chia sẻ khóa với Mallory.
    + Bob chia sẻ khóa khác với Mallory.
    + Mallory giải mã được tin nhắn, sửa nội dung, rồi mã hóa lại chuyển tiếp.
"""

from __future__ import annotations

from src.crypto import dh, aes


def run_mitm_demo() -> None:
    # Lấy tham số chung p, g
    p, g = dh.get_parameters()

    print("== Tham số hệ thống ==")
    print(f"p (prime) = {p}")
    print(f"g (base)  = {g}")
    print()

    # ----- Bước 1: Alice, Bob, Mallory sinh số bí mật ----- #
    a = dh.generate_private_exponent(p)   # bí mật của Alice
    b = dh.generate_private_exponent(p)   # bí mật của Bob
    m1 = dh.generate_private_exponent(p)  # bí mật của Mallory (kênh với Alice)
    m2 = dh.generate_private_exponent(p)  # bí mật của Mallory (kênh với Bob)

    A = pow(g, a, p)     # gửi từ Alice (g^a mod p)
    B = pow(g, b, p)     # gửi từ Bob   (g^b mod p)
    MA = pow(g, m1, p)   # Mallory gửi cho Bob (giả là A)
    MB = pow(g, m2, p)   # Mallory gửi cho Alice (giả là B)

    print("== Khởi tạo khóa công khai ban đầu ==")
    print(f"Alice: a = {a}, A = g^a mod p = {A}")
    print(f"Bob  : b = {b}, B = g^b mod p = {B}")
    print(f"Mallory: m1 = {m1}, g^m1 = {MA} (gửi cho Bob)")
    print(f"Mallory: m2 = {m2}, g^m2 = {MB} (gửi cho Alice)")
    print()

    # ----- Bước 2: Mallory chặn và thay thế A, B ----- #
    print("== Mallory chặn A, B và thay bằng giá trị của mình ==")
    print("Alice gửi A cho Bob  -> Mallory giữ lại A, gửi MA cho Bob.")
    print("Bob gửi B cho Alice -> Mallory giữ lại B, gửi MB cho Alice.")
    print()

    # ----- Bước 3: Mỗi bên tính khóa chung (nhưng thực ra là 2 khóa khác nhau) ----- #
    # Alice tưởng khóa chung với Bob, nhưng thực ra với Mallory
    s_Alice = pow(MB, a, p)       # (g^m2)^a
    s_Mallory_with_Alice = pow(A, m2, p)

    # Bob tưởng khóa chung với Alice, nhưng thực ra với Mallory
    s_Bob = pow(MA, b, p)         # (g^m1)^b
    s_Mallory_with_Bob = pow(B, m1, p)

    assert s_Alice == s_Mallory_with_Alice
    assert s_Bob == s_Mallory_with_Bob

    key_Alice = dh.derive_key_from_secret(s_Alice)
    key_Bob = dh.derive_key_from_secret(s_Bob)
    key_MA = dh.derive_key_from_secret(s_Mallory_with_Alice)
    key_MB = dh.derive_key_from_secret(s_Mallory_with_Bob)

    print("== Kết quả khóa chung (MITM thành công) ==")
    print(f"Khóa Alice <-> Mallory : secret_AM = {s_Alice}")
    print(f"Khóa Bob   <-> Mallory : secret_MB = {s_Bob}")
    print("Alice & Bob không có cùng một khóa chung.")
    print()

    # ----- Bước 4: Demo Mallory đọc & sửa tin nhắn ----- #
    plaintext_from_alice = "Hello Bob, this is Alice!"
    print("== Alice gửi tin nhắn cho Bob (thực tế đi qua Mallory) ==")
    print(f"Alice (plaintext): {plaintext_from_alice}")

    cipher_for_M = aes.encrypt_message(key_Alice, plaintext_from_alice)

    print("Mallory chặn được ciphertext, giải mã bằng khóa với Alice...")
    recovered_by_M = aes.decrypt_message(key_MA, cipher_for_M)
    print(f"Mallory đọc được    : {recovered_by_M}")

    # Mallory sửa nội dung
    modified = "Hello Bob, this is Mallory (đã sửa nội dung)!"
    cipher_to_B = aes.encrypt_message(key_MB, modified)

    print("Mallory mã hóa lại bằng khóa với Bob và chuyển tiếp...")
    decrypted_by_B = aes.decrypt_message(key_Bob, cipher_to_B)
    print(f"Bob cuối cùng nhận được: {decrypted_by_B}")
    print()
    print("=> Kết luận: DH thuần không có xác thực -> MITM đọc và sửa được tin nhắn.")


if __name__ == "__main__":
    run_mitm_demo()
