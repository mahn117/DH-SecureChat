<<<<<<< HEAD

# DH-SecureChat – Ứng dụng chat bảo mật dùng Diffie–Hellman

## 1. Giới thiệu

DH-SecureChat là một ứng dụng chat đơn giản minh họa cách xây dựng kênh liên lạc an toàn giữa hai người dùng dựa trên:

- Trao đổi khóa Diffie–Hellman (DH)
- Mã hóa đối xứng AES-GCM
- Demo tấn công Man-in-the-Middle (MITM) trên DH thuần
- Demo DH có xác thực bằng HMAC để chống MITM

Dự án được xây dựng phục vụ bài tập lớn môn **An ninh mạng**.

---

## 2. Tính năng chính

1. **Server relay** (không giải mã nội dung):
   - Nhận kết nối từ nhiều client
   - Lưu public key DH của từng user
   - Cấp public key peer theo yêu cầu
   - Chuyển tiếp ciphertext giữa các client
   - Không bao giờ thấy bản rõ (plaintext)

2. **Client chat bảo mật**:
   - Sinh cặp khóa Diffie–Hellman
   - Trao đổi public key qua server → tạo **shared key** 32 bytes
   - Dùng **AES-GCM** để mã hóa/giải mã tin nhắn
   - Giao diện GUI bằng Tkinter: danh sách user online, khung chat

3. **Demo tấn công MITM**:
   - `mitm_demo.py`: minh họa kịch bản Mallory đứng giữa Alice và Bob
   - `mitm_protected.py`: minh họa DH có xác thực HMAC, Mallory không giải mã được

---

## 3. Kiến trúc & cấu trúc thư mục

```text
DH-SecureChat/
│
├── README.md
├── requirements.txt
│
├── config/
│   ├── server.yaml       # Cấu hình IP/port server
│   └── client.yaml       # Cấu hình IP/port client
│
├── src/
│   ├── crypto/           # Lớp mật mã
│   │   ├── dh.py         # Diffie–Hellman + HKDF
│   │   ├── aes.py        # AES-GCM
│   │   └── auth.py       # HMAC-SHA256
│   │
│   ├── server/
│   │   ├── users.py      # Quản lý user online
│   │   ├── core.py       # Xử lý message từ client
│   │   └── main.py       # Chạy server
│   │
│   └── client/
│       ├── core.py       # Kết nối server, DH, AES
│       ├── gui.py        # Giao diện Tkinter
│       └── main.py       # Chạy client
│
├── examples/
│   ├── dh_basic_demo.py  # Demo DH tạo khóa chung
│   └── attack_compare.py # So sánh DH thuần vs DH + HMAC
│
└── tests/
    ├── test_dh.py        # Kiểm thử shared key = nhau
    └── test_aes.py       # Kiểm thử AES-GCM round-trip
```
