# examples/mitm_visual_demo.py
"""
GUI minh họa tấn công Man-in-the-Middle (MITM) trên Diffie–Hellman.

- DEMO 1: DH thuần – bạn đóng vai Mallory, tự sửa message giữa Alice và Bob.
- DEMO 2: DH + HMAC – minh họa:
    (A) Bắt tay hợp lệ -> thành công.
    (B) Attacker sửa public key -> HMAC FAIL -> handshake bị chặn.
"""

import tkinter as tk
from tkinter import ttk

from src.crypto.dh import (
    generate_keypair,
    derive_shared_key,
    public_key_bytes,
)
from src.crypto.aes import encrypt, decrypt
from src.crypto.auth import hmac_sign, hmac_verify


class MitmDemoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DH-SecureChat – MITM Visual Demo")
        self.root.geometry("950x600")
        self.root.minsize(860, 520)

        # Màu sắc
        self.bg_main = "#020617"
        self.bg_panel = "#020617"
        self.bg_widget = "#020617"
        self.fg_main = "#e5e7eb"
        self.accent = "#38bdf8"
        self.error_color = "#f97373"

        self.root.configure(bg=self.bg_main)
        self._setup_style()

        # Cho frame chính giãn theo cửa sổ
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)

        main = ttk.Frame(root, style="App.TFrame", padding=12)
        main.grid(row=0, column=0, sticky="nsew")
        main.rowconfigure(1, weight=1)
        main.columnconfigure(0, weight=1)

        # Header
        header = ttk.Frame(main, style="App.TFrame")
        header.grid(row=0, column=0, sticky="ew", pady=(4, 10))
        header.columnconfigure(0, weight=1)
        header.columnconfigure(1, weight=0)

        ttk.Label(
            header,
            text="MITM Demo – Diffie–Hellman",
            style="Title.TLabel",
        ).grid(row=0, column=0, sticky="w")

        ttk.Label(
            header,
            text="Môn An ninh mạng – Minh họa tấn công & phòng thủ",
            style="Subtitle.TLabel",
        ).grid(row=0, column=1, sticky="e")

        # Controls + log
        top = ttk.Frame(main, style="App.TFrame")
        top.grid(row=1, column=0, sticky="nsew")
        top.rowconfigure(0, weight=1)
        top.columnconfigure(0, weight=0)
        top.columnconfigure(1, weight=1)

        # Buttons bên trái
        btn_frame = ttk.Labelframe(
            top,
            text="Bước thao tác",
            style="Panel.TLabelframe",
            padding=10,
        )
        btn_frame.grid(row=0, column=0, sticky="nsw", padx=(0, 10))
        btn_frame.columnconfigure(0, weight=1)

        ttk.Button(
            btn_frame,
            text="1) DH thuần – Tôi đóng vai Mallory",
            style="Accent.TButton",
            command=self.run_plain_dh_mitm_step1,
        ).grid(row=0, column=0, sticky="ew", pady=4)

        ttk.Button(
            btn_frame,
            text="2) Gửi message đã sửa cho Bob",
            style="Accent.TButton",
            command=self.run_plain_dh_mitm_step2,
        ).grid(row=1, column=0, sticky="ew", pady=4)

        ttk.Separator(btn_frame, orient="horizontal").grid(
            row=2, column=0, sticky="ew", pady=8
        )

        ttk.Button(
            btn_frame,
            text="3) DH + HMAC (chống MITM)",
            style="Accent.TButton",
            command=self.run_authenticated_dh,
        ).grid(row=3, column=0, sticky="ew", pady=4)

        # Log bên phải
        log_frame = ttk.Labelframe(
            top,
            text="Diễn biến chi tiết",
            style="Panel.TLabelframe",
            padding=8,
        )
        log_frame.grid(row=0, column=1, sticky="nsew")
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)

        self.log = tk.Text(
            log_frame,
            height=22,
            wrap="word",
            bg=self.bg_widget,
            fg=self.fg_main,
            insertbackground=self.fg_main,
            relief="flat",
            font=("Consolas", 10),
        )
        self.log.grid(row=0, column=0, sticky="nsew")

        scroll = ttk.Scrollbar(log_frame, command=self.log.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.log.configure(yscrollcommand=scroll.set)

        # Khung Mallory sửa nội dung
        atk_frame = ttk.Labelframe(
            main,
            text="Mallory chỉnh sửa message (DEMO 1)",
            style="Panel.TLabelframe",
            padding=10,
        )
        atk_frame.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        atk_frame.columnconfigure(0, weight=1)

        ttk.Label(
            atk_frame,
            text="Nội dung sau khi Mallory đọc được (bạn có thể sửa trực tiếp ở đây):",
            style="Body.TLabel",
        ).grid(row=0, column=0, sticky="w")

        self.attack_text_var = tk.StringVar()
        atk_entry = tk.Entry(
            atk_frame,
            textvariable=self.attack_text_var,
            bg=self.bg_widget,
            fg=self.fg_main,
            insertbackground=self.fg_main,
            relief="flat",
            font=("Segoe UI", 10),
        )
        atk_entry.grid(row=1, column=0, sticky="ew", pady=4, ipady=4)

        ttk.Label(
            atk_frame,
            text="Sau khi chỉnh, bấm nút (2) để giả lập gửi cho Bob.",
            style="Subtitle.TLabel",
        ).grid(row=2, column=0, sticky="w", pady=(2, 0))

        # Trạng thái giữa bước 1 & 2
        self._mitm_state = None  # {"b_shared": ..., "original": ...}

    # ================== STYLE ==================

    def _setup_style(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure("App.TFrame", background=self.bg_main)
        style.configure("Panel.TFrame", background=self.bg_panel)

        style.configure(
            "Title.TLabel",
            background=self.bg_main,
            foreground=self.fg_main,
            font=("Segoe UI", 18, "bold"),
        )
        style.configure(
            "Subtitle.TLabel",
            background=self.bg_main,
            foreground="#9ca3af",
            font=("Segoe UI", 10),
        )
        style.configure(
            "Body.TLabel",
            background=self.bg_main,
            foreground=self.fg_main,
            font=("Segoe UI", 10),
        )
        style.configure(
            "Panel.TLabelframe",
            background=self.bg_main,
            foreground="#e5e7eb",
            font=("Segoe UI", 11, "bold"),
        )
        style.configure(
            "Panel.TLabelframe.Label",
            background=self.bg_main,
            foreground="#e5e7eb",
            font=("Segoe UI", 11, "bold"),
        )
        style.configure(
            "Accent.TButton",
            font=("Segoe UI", 10, "bold"),
            padding=8,
        )

    # ================== HỖ TRỢ UI ==================

    def _clear_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def _append(self, text, tag: str | None = None):
        self.log.configure(state="normal")
        if "info" not in self.log.tag_names():
            self.log.tag_configure("info", foreground="#a5b4fc")
            self.log.tag_configure("error", foreground=self.error_color)
            self.log.tag_configure("ok", foreground="#4ade80")

        if tag:
            self.log.insert("end", text + "\n", tag)
        else:
            self.log.insert("end", text + "\n")

        self.log.see("end")
        self.log.configure(state="disabled")

    # =========================================================
    # DEMO 1 – DH THUẦN, BẠN TỰ ĐÓNG VAI MALLORY
    # =========================================================

    def run_plain_dh_mitm_step1(self):
        """Bước 1: Thiết lập MITM, cho bạn xem và sửa message của Alice."""
        self._clear_log()
        self._mitm_state = None

        self._append("=== DEMO 1: Diffie–Hellman thuần – bạn đóng vai Mallory ===\n", "info")

        # Alice & Bob tưởng đang nói chuyện trực tiếp
        a_priv, a_pub = generate_keypair()
        b_priv, b_pub = generate_keypair()

        self._append("Alice sinh secret a, gửi public A cho Bob (trên kênh không an toàn).")
        self._append("Bob sinh secret b, gửi public B cho Alice.\n")

        # Mallory đứng giữa, tạo 2 cặp khóa riêng
        m1_priv, m1_pub = generate_keypair()  # giả làm Bob với Alice
        m2_priv, m2_pub = generate_keypair()  # giả làm Alice với Bob

        self._append("Mallory tạo 2 cặp khóa riêng:")
        self._append("  - (m1_priv, m1_pub): dùng khi nói chuyện với Alice (giả làm Bob).")
        self._append("  - (m2_priv, m2_pub): dùng khi nói chuyện với Bob (giả làm Alice).\n")

        # Alice nhận public key “của Bob” nhưng thực chất là m1_pub
        a_shared = derive_shared_key(a_priv, m1_pub)
        # Bob nhận public key “của Alice” nhưng thực chất là m2_pub
        b_shared = derive_shared_key(b_priv, m2_pub)

        # Mallory cũng tính được 2 khóa tương ứng
        m_with_a = derive_shared_key(m1_priv, a_pub)
        m_with_b = derive_shared_key(m2_priv, b_pub)

        self._append("Khóa chung hình thành:")
        self._append(f"  - Khóa Alice <-> Mallory (K_AM)  = {a_shared.hex()[:16]}...")
        self._append(f"  - Khóa Bob   <-> Mallory (K_MB)  = {b_shared.hex()[:16]}...")
        self._append("  - Hai khóa này KHÁC NHAU, nhưng Alice và Bob đều không biết.\n")

        # Alice gửi tin cho Bob
        msg = b"Hello Bob, this is Alice!"
        self._append(f"Alice định gửi cho Bob (plaintext gốc): {msg.decode()}")

        # Alice mã hóa bằng K_AM (nhưng cô ấy tưởng là khóa với Bob)
        ciphertext = encrypt(a_shared, msg)
        self._append("Alice mã hóa message bằng K_AM và gửi ciphertext qua kênh.\n")

        # Mallory chặn và đọc được bằng K_AM
        stolen = decrypt(m_with_a, ciphertext)
        stolen_text = stolen.decode()
        self._append("Mallory chặn ciphertext, giải mã bằng K_AM và đọc được:", "info")
        self._append(f"  -> {stolen_text}\n")

        # Cho bạn (Mallory) sửa nội dung ở ô phía dưới
        self.attack_text_var.set(stolen_text)
        self._append(
            "Bây giờ bạn đang đóng vai Mallory.\n"
            "Hãy sửa nội dung ở ô bên dưới rồi bấm nút "
            "“2) Gửi message đã sửa cho Bob”.",
            "info",
        )

        # Lưu b_shared để bước 2 dùng lại
        self._mitm_state = {
            "b_shared": b_shared,
            "original": stolen_text,
        }

    def run_plain_dh_mitm_step2(self):
        """Bước 2: Lấy nội dung bạn sửa, gửi cho Bob, và xem Bob nhận gì."""
        if not self._mitm_state:
            self._append(
                "\n[!] Bạn chưa chạy bước 1. Hãy bấm "
                "“1) DH thuần – Tôi đóng vai Mallory” trước.",
                "error",
            )
            return

        tampered_text = self.attack_text_var.get().strip()
        if not tampered_text:
            self._append("\n[!] Nội dung sửa đang trống, không có gì để gửi cho Bob.", "error")
            return

        b_shared = self._mitm_state["b_shared"]

        self._append("\n--- BƯỚC 2: Mallory gửi message đã sửa cho Bob ---", "info")
        self._append("Mallory quyết định gửi cho Bob nội dung:")
        self._append(f"  -> {tampered_text}")

        # Mallory mã hóa lại message bằng khóa với Bob
        payload2 = encrypt(b_shared, tampered_text.encode("utf-8"))
        self._append("Mallory mã hóa message bằng K_MB và gửi ciphertext cho Bob.")

        # Bob giải mã
        received = decrypt(b_shared, payload2).decode("utf-8")
        self._append("Bob giải mã bằng K_MB và nhận được:", "ok")
        self._append(f"  -> {received}\n", "ok")

        self._append("Kết luận DEMO 1:", "info")
        self._append(
            "  - Bạn (Mallory) có thể đọc và chỉnh sửa toàn bộ nội dung "
            "giữa Alice và Bob khi dùng DH thuần (không có xác thực).",
            "info",
        )

    # =========================================================
    # DEMO 2 – DH CÓ XÁC THỰC HMAC
    # =========================================================

    def run_authenticated_dh(self):
        """
        Demo 2 có 2 phần:
          (A) Bắt tay hợp lệ (không có attacker) -> thành công.
          (B) Giả lập attacker sửa public key A -> HMAC FAIL -> handshake bị chặn.
        """
        self._clear_log()
        self._mitm_state = None

        self._append("=== DEMO 2: Diffie–Hellman + HMAC (chống MITM) ===\n", "info")

        # Hai bên có sẵn một khóa bí mật chung (PSK)
        psk = b"demo-psk-very-secret"
        self._append("Giả sử Alice & Bob đã chia sẻ trước một khóa bí mật PSK.")
        self._append("Khi gửi public key DH, mỗi bên gửi kèm HMAC(PSK, public_key).")
        self._append("Tách thành 2 kịch bản: (A) không có attacker, (B) attacker sửa A.\n")

        # -------------------- (A) KHÔNG CÓ ATTACKER --------------------
        self._append(">>> (A) Kịch bản không có attacker, HMAC hợp lệ <<<\n", "info")

        # Sinh cặp khóa DH
        a_priv, a_pub = generate_keypair()
        b_priv, b_pub = generate_keypair()

        # Alice gửi A + tagA
        a_pub_bytes = public_key_bytes(a_pub)
        a_tag = hmac_sign(psk, a_pub_bytes)
        self._append("Alice gửi (A, HMAC(PSK, A)) cho Bob.")

        # Bob verify A
        if not hmac_verify(psk, a_pub_bytes, a_tag):
            self._append(
                "Bob phát hiện HMAC(A) sai -> public key đã bị sửa! (KHÔNG mong muốn ở case A)",
                "error",
            )
            return
        self._append("Bob verify HMAC(A) thành công -> public key A là hợp lệ.\n", "ok")

        # Bob gửi B + tagB
        b_pub_bytes = public_key_bytes(b_pub)
        b_tag = hmac_sign(psk, b_pub_bytes)
        self._append("Bob gửi (B, HMAC(PSK, B)) cho Alice.")

        # Alice verify B
        if not hmac_verify(psk, b_pub_bytes, b_tag):
            self._append(
                "Alice phát hiện HMAC(B) sai -> public key đã bị sửa! (KHÔNG mong muốn ở case A)",
                "error",
            )
            return
        self._append("Alice verify HMAC(B) thành công -> public key B là hợp lệ.\n", "ok")

        # Tính shared key
        a_shared = derive_shared_key(a_priv, b_pub)
        b_shared = derive_shared_key(b_priv, a_pub)

        self._append("Sau khi xác thực public key, hai bên tính khóa chung:", "info")
        self._append(f"  - K = {a_shared.hex()[:32]}...", "info")
        self._append("  - Alice và Bob có cùng một khóa, attacker không biết được khóa này.\n", "info")

        # Demo mã hóa/giải mã
        msg = b"Hello with authenticated DH!"
        self._append(f"Alice gửi thông điệp: {msg.decode()}")
        ciphertext = encrypt(a_shared, msg)
        self._append("Alice mã hóa message bằng AES-GCM với khóa K và gửi cho Bob.")

        out = decrypt(b_shared, ciphertext)
        self._append("Bob giải mã bằng cùng khóa K và nhận được:", "ok")
        self._append(f"  -> {out.decode()}\n", "ok")

        # -------------------- (B) ATTACKER SỬA PUBLIC KEY A --------------------
        self._append(">>> (B) Giả lập attacker sửa public key A trên đường đi <<<\n", "info")

        # Attacker sửa A trên đường đi (flip 1 bit)
        fake_a_pub_bytes = bytearray(a_pub_bytes)
        fake_a_pub_bytes[0] ^= 0x01  # đổi 1 bit bất kỳ

        self._append("Giả sử attacker thay A bằng A' (khác A) nhưng KHÔNG biết PSK.")
        self._append("Hắn chỉ có thể gửi (A', tagA cũ) hoặc HMAC rác.\n")

        # Bob nhận (A', tagA) và verify HMAC với PSK
        ok = hmac_verify(psk, bytes(fake_a_pub_bytes), a_tag)
        if not ok:
            self._append("Bob verify HMAC(A') với tagA và PSK:", "info")
            self._append("  -> KẾT QUẢ: FAIL ❌ (HMAC không khớp)", "error")
            self._append(
                "Bob KẾT LUẬN: public key bị sửa trên đường đi -> dừng bắt tay.",
                "error",
            )
            self._append(
                "=> Handshake không hoàn thành, không sinh được khóa chung, attacker không MITM được.\n",
                "info",
            )
        else:
            self._append("(!) HMAC(A') lại verify đúng (xác suất lý thuyết cực kỳ nhỏ).", "error")

        self._append("Kết luận DEMO 2:", "info")
        self._append(
            "  - Với HMAC + PSK, mọi sửa đổi trên public key sẽ bị phát hiện ở bước verify.\n"
            "  - Vì handshake sẽ bị HỦY ngay tại bước xác thực, attacker không thể thiết lập "
            "hai khóa khác nhau như trong DEMO 1.\n"
            "  - Trong thực tế, thay vì HMAC-PSK, người ta thường dùng chữ ký số / chứng chỉ số (PKI) như HTTPS.",
            "info",
        )


def main():
    print("[MITM DEMO] Starting GUI...")
    root = tk.Tk()
    MitmDemoApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
