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
│   │   ├── __init__.py
│   │   ├── dh.py         # Diffie–Hellman + HKDF
│   │   ├── aes.py        # AES-GCM
│   │   └── auth.py       # HMAC-SHA256
│   │
│   ├── server/
│   │   ├── __init__.py
│   │   ├── users.py      # Quản lý user online
│   │   ├── core.py       # Xử lý message từ client
│   │   └── main.py       # Chạy server
│   │
│   ├── client/
│   │   ├── __init__.py
│   │   ├── core.py       # Kết nối server, DH, AES
│   │   ├── gui.py        # Giao diện Tkinter
│   │   └── main.py       # Chạy client
│   │
│   └── attacks/
│       ├── __init__.py
│       ├── mitm_demo.py       # Demo tấn công MITM cơ bản
│       ├── mitm_patch.py      # Tấn công MITM với patch
│       └── mitm_protected.py  # DH + HMAC chống MITM
│
├── examples/
│   ├── __init__.py
│   ├── dh_basic_demo.py        # Demo DH tạo khóa chung
│   ├── attack_compare.py       # So sánh DH thuần vs DH + HMAC
│   └── mitm_visual_demo.py     # Mô phỏng trực quan tấn công MITM
│
└── tests/
    ├── __init__.py
    ├── test_dh.py              # Kiểm thử shared key = nhau
    └── test_aes.py             # Kiểm thử AES-GCM round-trip
```

---

## 4. Hướng dẫn cài đặt

### Yêu cầu
- Python 3.8+
- Các thư viện trong `requirements.txt`

### Cài đặt thư viện
```bash
pip install -r requirements.txt
```

---

## 5. Hướng dẫn sử dụng

### Chạy Server
```bash
python src/server/main.py
```
Server sẽ lắng nghe trên IP/port từ `config/server.yaml`

### Chạy Client
```bash
python src/client/main.py
```
Giao diện GUI sẽ hiển thị:
- Danh sách user online
- Ô nhập tin nhắn
- Khung hiển thị lịch sử chat

---

## 6. Chạy Demo và Test

### Demo DH cơ bản
```bash
python examples/dh_basic_demo.py
```

### Demo tấn công MITM có hình ảnh
```bash
python examples/mitm_visual_demo.py
```

### So sánh DH vs DH+HMAC
```bash
python examples/attack_compare.py
```

### Chạy Unit Tests
```bash
python -m pytest tests/
```

---

## 7. Giải thích chi tiết

### Diffie–Hellman Exchange
- Mỗi bên sinh cặp khóa riêng/công khai
- Trao đổi khóa công khai qua server
- Tính shared secret dùng khóa riêng của mình + khóa công khai của đối phương

### AES-GCM Encryption
- Mã hóa đối xứng: cả hai bên dùng **shared secret** làm khóa
- GCM mode: vừa mã hóa vừa xác thực (AEAD)
- Ngăn chặn tấn công replay

### MITM Attack Scenarios
- **mitm_demo.py**: Mallory tạo khóa riêng với cả Alice và Bob, lấy được shared secret của mỗi bên
- **mitm_protected.py**: Alice/Bob xác thực DH bằng HMAC(secret, message), Mallory không có secret nên không giả mạo được

---

## 8. Tác giả
- Dự án là bài tập lớn môn An ninh mạng