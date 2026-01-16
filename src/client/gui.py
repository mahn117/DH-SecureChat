# src/client/gui.py
from __future__ import annotations

import hmac
import hashlib
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from datetime import datetime
from typing import Dict, Any, Optional

from .core import SecureChatClient


class ChatGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root

        # Bảng màu giao diện
        self.colors: Dict[str, str] = {
            "primary": "#2c3e50",
            "primary_light": "#3498db",
            "secondary": "#ecf0f1",
            "background": "#ffffff",
            "surface": "#f8f9fa",
            "border": "#dfe6e9",
            "text_primary": "#2d3436",
            "text_secondary": "#636e72",
            "text_light": "#b2bec3",
            "success": "#27ae60",
            "warning": "#f39c12",
            "error": "#e74c3c",
        }

        self.root.title("DH-SecureChat")
        self.root.minsize(1100, 700)

        # Trạng thái runtime
        self.client: Optional[SecureChatClient] = None
        self.username: str = ""
        self.current_peer: Optional[str] = None
        # peer -> thông tin DH dùng để hiển thị / trạng thái
        self.dh_info: Dict[str, Dict[str, Any]] = {}

        # Thiết lập style + layout
        self._setup_style()

        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)

        self.main = ttk.Frame(self.root)
        self.main.grid(row=0, column=0, sticky="nsew")
        self.main.rowconfigure(0, weight=0)
        self.main.rowconfigure(1, weight=1)
        self.main.columnconfigure(0, weight=1)

        self._build_header()
        self._build_body()

        # Đăng nhập & kết nối
        self._login_and_connect()

    # ============================================================
    # STYLE
    # ============================================================

    def _setup_style(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("Header.TFrame", background="#f5f6fa")
        style.configure("TFrame", background="#ffffff")
        style.configure("TLabelframe", background="#ffffff")
        style.configure("TLabelframe.Label", background="#ffffff")

    # ============================================================
    # HEADER
    # ============================================================

    def _build_header(self) -> None:
        header = ttk.Frame(self.main, style="Header.TFrame", padding=10)
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)
        header.columnconfigure(1, weight=0)

        # Bên trái: tiêu đề
        left = ttk.Frame(header, style="Header.TFrame")
        left.grid(row=0, column=0, sticky="w")

        tk.Label(
            left,
            text="DH-SecureChat",
            font=("Segoe UI", 16, "bold"),
            bg="#f5f6fa",
            fg=self.colors["primary"],
        ).pack(anchor="w")

        tk.Label(
            left,
            text="Trao đổi khóa an toàn & trò chuyện mã hóa đầu-cuối",
            font=("Segoe UI", 9),
            bg="#f5f6fa",
            fg="#555555",
        ).pack(anchor="w")

        # Bên phải: tên người dùng + trạng thái kết nối
        right = ttk.Frame(header, style="Header.TFrame")
        right.grid(row=0, column=1, sticky="e")

        self.lbl_username_header = tk.Label(
            right,
            text="Chưa đăng nhập",
            font=("Segoe UI", 10, "bold"),
            bg="#f5f6fa",
            fg=self.colors["primary"],
        )
        self.lbl_username_header.pack(anchor="e")

        self.lbl_status = tk.Label(
            right,
            text="● Chưa kết nối",
            font=("Segoe UI", 9),
            bg="#f5f6fa",
            fg=self.colors["error"],
        )
        self.lbl_status.pack(anchor="e")

    # ============================================================
    # BODY (3 CỘT)
    # ============================================================

    def _build_body(self) -> None:
        body = ttk.Frame(self.main, padding=10)
        body.grid(row=1, column=0, sticky="nsew")
        body.rowconfigure(0, weight=1)

        # Giữ tỉ lệ: user (nhỏ) – chat (rộng nhất) – DH (vừa)
        body.columnconfigure(0, weight=1, minsize=230)   # danh sách người dùng
        body.columnconfigure(1, weight=4, minsize=480)   # khung chat
        body.columnconfigure(2, weight=3, minsize=260)   # khung DH / MITM

        self._build_user_panel(body)
        self._build_chat_panel(body)
        self._build_dh_panel(body)

    # ============================================================
    # PANEL NGƯỜI DÙNG
    # ============================================================

    def _build_user_panel(self, parent: ttk.Frame) -> None:
        frame = ttk.Labelframe(parent, text="Người dùng trực tuyến", padding=8)
        frame.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        frame.rowconfigure(1, weight=1)
        frame.columnconfigure(0, weight=1)

        # Header
        header = ttk.Frame(frame)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        header.columnconfigure(0, weight=1)

        tk.Label(
            header,
            text="Kết nối đang hoạt động",
            font=("Segoe UI", 10, "bold"),
            anchor="w",
        ).grid(row=0, column=0, sticky="w")

        self.lbl_user_count = tk.Label(
            header,
            text="0",
            font=("Segoe UI", 10, "bold"),
            fg=self.colors["primary_light"],
        )
        self.lbl_user_count.grid(row=0, column=1, sticky="e")

        # Listbox + scrollbar
        list_container = ttk.Frame(frame)
        list_container.grid(row=1, column=0, sticky="nsew")
        list_container.rowconfigure(0, weight=1)
        list_container.columnconfigure(0, weight=1)

        self.user_listbox = tk.Listbox(
            list_container,
            font=("Segoe UI", 10),
            activestyle="none",
            selectbackground=self.colors["primary_light"],
            selectforeground="white",
        )
        self.user_listbox.grid(row=0, column=0, sticky="nsew")

        sb_users = ttk.Scrollbar(
            list_container,
            orient="vertical",
            command=self.user_listbox.yview,
        )
        sb_users.grid(row=0, column=1, sticky="ns")
        self.user_listbox.configure(yscrollcommand=sb_users.set)

        self.user_listbox.bind("<<ListboxSelect>>", self._on_user_selected)

        # Nút
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=2, column=0, sticky="ew", pady=(6, 0))
        btn_frame.columnconfigure(0, weight=1)
        btn_frame.columnconfigure(1, weight=1)

        self.btn_setup_dh = ttk.Button(
            btn_frame,
            text="Thiết lập khóa DH",
            command=self._start_dh_with_selected,
        )
        self.btn_setup_dh.grid(row=0, column=0, sticky="ew", padx=(0, 4))

        btn_refresh = ttk.Button(
            btn_frame,
            text="Làm mới",
            command=self._refresh_users,
        )
        btn_refresh.grid(row=0, column=1, sticky="ew", padx=(4, 0))

    # ============================================================
    # PANEL CHAT
    # ============================================================

    def _build_chat_panel(self, parent: ttk.Frame) -> None:
        frame = ttk.Labelframe(parent, text="Trò chuyện an toàn", padding=8)
        frame.grid(row=0, column=1, sticky="nsew", padx=(0, 8))
        frame.rowconfigure(1, weight=1)
        frame.columnconfigure(0, weight=1)

        # Trên: tên peer + trạng thái mã hóa
        top = ttk.Frame(frame)
        top.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        top.columnconfigure(0, weight=1)

        self.lbl_chat_with = tk.Label(
            top,
            text="Chọn một người dùng để bắt đầu trò chuyện",
            font=("Segoe UI", 10, "bold"),
            anchor="w",
        )
        self.lbl_chat_with.grid(row=0, column=0, sticky="w")

        self.lbl_encryption_status = tk.Label(
            top,
            text="🔓 Chưa mã hóa",
            font=("Segoe UI", 9),
            fg=self.colors["text_secondary"],
        )
        self.lbl_encryption_status.grid(row=0, column=1, sticky="e")

        # Khu vực hiển thị tin nhắn
        text_container = ttk.Frame(frame)
        text_container.grid(row=1, column=0, sticky="nsew", pady=(0, 5))
        text_container.rowconfigure(0, weight=1)
        text_container.columnconfigure(0, weight=1)

        self.chat_text = tk.Text(
            text_container,
            state="disabled",
            wrap="word",
            font=("Segoe UI", 10),
        )
        self.chat_text.grid(row=0, column=0, sticky="nsew")

        sb_chat = ttk.Scrollbar(
            text_container,
            orient="vertical",
            command=self.chat_text.yview,
        )
        sb_chat.grid(row=0, column=1, sticky="ns")
        self.chat_text.configure(yscrollcommand=sb_chat.set)

        # Hàng nhập tin
        bottom = ttk.Frame(frame)
        bottom.grid(row=2, column=0, sticky="ew")
        bottom.columnconfigure(0, weight=1)

        self.entry_message = ttk.Entry(bottom, font=("Segoe UI", 10))
        self.entry_message.grid(row=0, column=0, sticky="ew", padx=(0, 4))
        self.entry_message.bind("<Return>", self._on_send_clicked)

        btn_send = ttk.Button(
            bottom,
            text="Gửi",
            command=self._on_send_clicked,
        )
        btn_send.grid(row=0, column=1, sticky="ew")

    # ============================================================
    # PANEL DH (NOTEBOOK TABS)
    # ============================================================

    def _build_dh_panel(self, parent: ttk.Frame) -> None:
        frame = ttk.Labelframe(parent, text="Trao đổi khóa Diffie–Hellman", padding=8)
        frame.grid(row=0, column=2, sticky="nsew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        self.dh_notebook = ttk.Notebook(frame)
        self.dh_notebook.grid(row=0, column=0, sticky="nsew")

        tab_current = ttk.Frame(self.dh_notebook)
        tab_mitm = ttk.Frame(self.dh_notebook)

        self.dh_notebook.add(tab_current, text="Phiên hiện tại")
        self.dh_notebook.add(tab_mitm, text="Mô phỏng MITM")

        self._build_dh_current_tab(tab_current)
        self._build_mitm_tab(tab_mitm)

    # ---------- TAB PHIÊN HIỆN TẠI ----------

    def _build_dh_current_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=1)

        self.lbl_session_peer = tk.Label(
            parent,
            text="Không có phiên nào đang hoạt động",
            font=("Segoe UI", 12, "bold"),
            anchor="w",
        )
        self.lbl_session_peer.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 2))

        tk.Label(
            parent,
            text="Tham số trao đổi khóa Diffie–Hellman",
            font=("Segoe UI", 9),
            anchor="w",
        ).grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 6))

        params = ttk.Frame(parent)
        params.grid(row=2, column=0, sticky="ew", padx=8)
        params.columnconfigure(1, weight=1)

        rows = [
            ("Số nguyên tố p:", "p_value"),
            ("Căn nguyên thủy g:", "g_value"),
            ("Khóa công khai của bạn (A):", "A_value"),
            ("Khóa công khai của đối phương (B):", "B_value"),
            ("Khóa bí mật chung:", "secret_value"),
        ]

        for i, (label, name) in enumerate(rows):
            tk.Label(params, text=label, anchor="w").grid(
                row=i, column=0, sticky="w", pady=3
            )
            lbl_val = tk.Label(
                params,
                text="–",
                anchor="w",
                font=("Consolas", 9),
                fg=self.colors["text_secondary"]
                if name != "secret_value"
                else self.colors["success"],
            )
            lbl_val.grid(row=i, column=1, sticky="ew", pady=3)
            setattr(self, f"lbl_{name}", lbl_val)

        status_frame = ttk.Frame(parent)
        status_frame.grid(row=3, column=0, sticky="ew", padx=8, pady=(16, 8))
        status_frame.columnconfigure(1, weight=1)

        tk.Label(status_frame, text="🔒", font=("Segoe UI", 20)).grid(
            row=0, column=0, rowspan=2, sticky="n", padx=(0, 8)
        )

        self.lbl_status_title = tk.Label(
            status_frame,
            text="Trạng thái mã hóa",
            font=("Segoe UI", 10, "bold"),
            anchor="w",
        )
        self.lbl_status_title.grid(row=0, column=1, sticky="ew")

        self.lbl_status_desc = tk.Label(
            status_frame,
            text="Chưa có phiên mã hóa nào được thiết lập.",
            font=("Segoe UI", 9),
            anchor="w",
            wraplength=320,
        )
        self.lbl_status_desc.grid(row=1, column=1, sticky="ew")

    # ---------- TAB MÔ PHỎNG MITM (CÓ SCROLLBAR) ----------

    def _build_mitm_tab(self, parent: ttk.Frame) -> None:
        # Tab MITM có canvas + scrollbar dọc để tránh bị thừa khoảng trắng
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)

        canvas = tk.Canvas(parent, borderwidth=0, highlightthickness=0)
        vscroll = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vscroll.set)

        canvas.grid(row=0, column=0, sticky="nsew")
        vscroll.grid(row=0, column=1, sticky="ns")

        # Frame thật bên trong canvas chứa toàn bộ nội dung MITM
        root_frame = ttk.Frame(canvas)
        window_id = canvas.create_window((0, 0), window=root_frame,
                                         anchor="nw", tags=("inner",))

        # Cập nhật scrollregion khi nội dung thay đổi
        def _on_frame_config(event):
            canvas.configure(scrollregion=canvas.bbox("all"))

        root_frame.bind("<Configure>", _on_frame_config)

        # Giữ cho frame rộng bằng canvas
        def _on_canvas_config(event):
            canvas.itemconfigure(window_id, width=event.width)

        canvas.bind("<Configure>", _on_canvas_config)

        # ------------------------------------------------------------------
        # 1. Tấn công MITM trên DH thuần (không xác thực)
        # ------------------------------------------------------------------
        root_frame.columnconfigure(0, weight=1)
        row = 0

        tk.Label(
            root_frame,
            text="1. Tấn công MITM trên DH thuần",
            font=("Segoe UI", 11, "bold"),
            anchor="w",
        ).grid(row=row, column=0, sticky="ew", padx=8, pady=(8, 2))
        row += 1

        tk.Label(
            root_frame,
            text=(
                "Mô hình: Alice ↔ Mallory ↔ Bob. Mallory chặn A, B và thay thế "
                "bằng A', B' để thiết lập hai khóa riêng với từng phía."
            ),
            font=("Segoe UI", 9),
            anchor="w",
            wraplength=380,
            justify="left",
        ).grid(row=row, column=0, sticky="ew", padx=8, pady=(0, 6))
        row += 1

        frm_inputs = ttk.Frame(root_frame)
        frm_inputs.grid(row=row, column=0, sticky="ew", padx=8)
        frm_inputs.columnconfigure(1, weight=1)
        row += 1

        def add_inp(r, text, default, attr_name):
            tk.Label(frm_inputs, text=text, anchor="w").grid(
                row=r, column=0, sticky="w", pady=2
            )
            e = ttk.Entry(frm_inputs, width=12)
            e.insert(0, default)
            e.grid(row=r, column=1, sticky="w", pady=2)
            setattr(self, attr_name, e)

        add_inp(0, "Số nguyên tố p:", "23", "mitm_p_entry")
        add_inp(1, "Căn nguyên thủy g:", "5", "mitm_g_entry")
        add_inp(2, "Bí mật của Alice (a):", "6", "mitm_a_entry")
        add_inp(3, "Bí mật của Bob (b):", "15", "mitm_b_entry")
        add_inp(4, "Bí mật Mallory m1 (phía Bob):", "7", "mitm_m1_entry")
        add_inp(5, "Bí mật Mallory m2 (phía Alice):", "11", "mitm_m2_entry")

        ttk.Button(
            root_frame,
            text="Chạy mô phỏng tấn công MITM",
            command=self._run_mitm_attack_demo,
        ).grid(row=row, column=0, sticky="ew", padx=8, pady=(8, 4))
        row += 1

        frm_res1 = ttk.Frame(root_frame)
        frm_res1.grid(row=row, column=0, sticky="ew", padx=8, pady=(2, 4))
        frm_res1.columnconfigure(1, weight=1)
        row += 1

        def add_res1(r, text, attr_name):
            tk.Label(frm_res1, text=text, anchor="w").grid(
                row=r, column=0, sticky="w", pady=2
            )
            lbl = tk.Label(
                frm_res1,
                text="–",
                anchor="w",
                font=("Consolas", 9),
            )
            lbl.grid(row=r, column=1, sticky="ew", pady=2)
            setattr(self, attr_name, lbl)

        add_res1(0, "Khóa của Alice K_A =", "lbl_mitm_KA")
        add_res1(1, "Khóa Mallory–Alice K_AM =", "lbl_mitm_Kam")
        add_res1(2, "Khóa của Bob K_B =", "lbl_mitm_KB")
        add_res1(3, "Khóa Mallory–Bob K_MB =", "lbl_mitm_Kmb")

        self.lbl_mitm_plain_status = tk.Label(
            root_frame,
            text="Kết quả: –",
            font=("Segoe UI", 9),
            fg=self.colors["error"],
            anchor="w",
            wraplength=380,
            justify="left",
        )
        self.lbl_mitm_plain_status.grid(row=row, column=0, sticky="ew",
                                        padx=8, pady=(0, 8))
        row += 1

        # ------------------------------------------------------------------
        # 2. DH + xác thực HMAC
        # ------------------------------------------------------------------
        tk.Label(
            root_frame,
            text="2. DH + xác thực HMAC",
            font=("Segoe UI", 11, "bold"),
            anchor="w",
        ).grid(row=row, column=0, sticky="ew", padx=8, pady=(8, 2))
        row += 1

        tk.Label(
            root_frame,
            text=(
                "Alice và Bob chia sẻ trước một khóa xác thực dài hạn K_auth. "
                "Họ tính HMAC(K_auth, p|g|A|B) để xác thực transcript DH. "
                "Nếu Mallory thay đổi A hoặc B, thẻ HMAC sẽ khác nhau."
            ),
            font=("Segoe UI", 9),
            anchor="w",
            justify="left",
            wraplength=380,
        ).grid(row=row, column=0, sticky="ew", padx=8, pady=(0, 6))
        row += 1

        frm_auth = ttk.Frame(root_frame)
        frm_auth.grid(row=row, column=0, sticky="ew", padx=8)
        frm_auth.columnconfigure(1, weight=1)
        row += 1

        tk.Label(frm_auth, text="Khóa xác thực dùng chung K_auth:", anchor="w").grid(
            row=0, column=0, sticky="w", pady=2
        )
        self.mitm_k_auth_entry = ttk.Entry(frm_auth, width=18)
        self.mitm_k_auth_entry.insert(0, "demo-auth-key")
        self.mitm_k_auth_entry.grid(row=0, column=1, sticky="ew", pady=2)

        self.mitm_simulate_var = tk.IntVar(value=1)
        ttk.Checkbutton(
            root_frame,
            text="Mô phỏng MITM (thay A, B bằng A', B')",
            variable=self.mitm_simulate_var,
        ).grid(row=row, column=0, sticky="w", padx=8, pady=(4, 4))
        row += 1

        ttk.Button(
            root_frame,
            text="Chạy mô phỏng DH + HMAC",
            command=self._run_dh_hmac_demo,
        ).grid(row=row, column=0, sticky="ew", padx=8, pady=(4, 4))
        row += 1

        # Khối kết quả: thẻ HMAC Alice, Bob, trạng thái
        result_frame = ttk.Labelframe(root_frame, text="Kết quả DH + HMAC", padding=4)
        result_frame.grid(row=row, column=0, sticky="ew", padx=8, pady=(2, 8))
        result_frame.columnconfigure(1, weight=1)

        tk.Label(result_frame, text="Thẻ HMAC của Alice:", anchor="w").grid(
            row=0, column=0, sticky="w", pady=2
        )
        self.lbl_mitm_hmac_alice = tk.Label(
            result_frame,
            text="–",
            anchor="w",
            font=("Consolas", 9),
        )
        self.lbl_mitm_hmac_alice.grid(row=0, column=1, sticky="ew", pady=2)

        tk.Label(result_frame, text="Thẻ HMAC của Bob:", anchor="w").grid(
            row=1, column=0, sticky="w", pady=2
        )
        self.lbl_mitm_hmac_bob = tk.Label(
            result_frame,
            text="–",
            anchor="w",
            font=("Consolas", 9),
        )
        self.lbl_mitm_hmac_bob.grid(row=1, column=1, sticky="ew", pady=2)

        self.lbl_mitm_hmac_status = tk.Label(
            result_frame,
            text="Kết quả: –",
            font=("Segoe UI", 9),
            anchor="w",
            wraplength=360,
            justify="left",
        )
        self.lbl_mitm_hmac_status.grid(row=2, column=0, columnspan=2,
                                       sticky="ew", pady=(4, 0))

    # ---------- LOGIC DEMO DH + HMAC ----------

    def _run_dh_hmac_demo(self) -> None:
        """Mô phỏng cách HMAC phát hiện / ngăn chặn MITM trên DH."""
        try:
            p = int(self.mitm_p_entry.get().strip())
            g = int(self.mitm_g_entry.get().strip())
            a = int(self.mitm_a_entry.get().strip())
            b = int(self.mitm_b_entry.get().strip())
            m1 = int(self.mitm_m1_entry.get().strip())
            m2 = int(self.mitm_m2_entry.get().strip())
        except ValueError:
            messagebox.showerror(
                "Dữ liệu không hợp lệ",
                "Vui lòng nhập các số nguyên cho p, g, a, b, m1, m2.",
            )
            return

        k_auth = self.mitm_k_auth_entry.get().encode("utf-8") or b"demo-auth-key"

        # DH trung thực
        A = pow(g, a, p)
        B = pow(g, b, p)

        simulate_mitm = bool(self.mitm_simulate_var.get())
        if simulate_mitm:
            A_seen_by_bob = pow(g, m1, p)   # A' phía Bob nhìn thấy
            B_seen_by_alice = pow(g, m2, p) # B' phía Alice nhìn thấy
        else:
            A_seen_by_bob = A
            B_seen_by_alice = B

        transcript_alice = f"{p}|{g}|{A}|{B_seen_by_alice}"
        transcript_bob = f"{p}|{g}|{A_seen_by_bob}|{B}"

        tag_alice = hmac.new(
            k_auth, transcript_alice.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        tag_bob = hmac.new(
            k_auth, transcript_bob.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        def short(s: str, n: int = 32) -> str:
            return s if len(s) <= n else s[:n] + "..."

        self.lbl_mitm_hmac_alice.config(text=short(tag_alice))
        self.lbl_mitm_hmac_bob.config(text=short(tag_bob))

        if tag_alice == tag_bob:
            self.lbl_mitm_hmac_status.config(
                text=(
                    "Kết quả: xác thực HMAC THÀNH CÔNG – cả hai phía thấy cùng một "
                    "transcript (p, g, A, B). Không phát hiện tấn công MITM."
                ),
                fg=self.colors["success"],
            )
        else:
            self.lbl_mitm_hmac_status.config(
                text=(
                    "Kết quả: xác thực HMAC THẤT BẠI – Alice và Bob tính ra thẻ HMAC "
                    "khác nhau. Nếu Mallory thay đổi A/B thì sẽ bị phát hiện."
                ),
                fg=self.colors["error"],
            )

    # ============================================================
    # ĐĂNG NHẬP + KẾT NỐI
    # ============================================================

    def _login_and_connect(self) -> None:
        username = simpledialog.askstring(
            "Đăng nhập", "Nhập tên người dùng:", parent=self.root
        )
        if not username:
            self.root.destroy()
            return

        self.username = username.strip()
        self.root.title(f"DH-SecureChat – {self.username}")
        self.lbl_username_header.config(text=self.username)

        self.lbl_status.config(text="● Đang kết nối...", fg=self.colors["warning"])

        self.client = SecureChatClient(
            username=self.username,
            host="127.0.0.1",
            port=5000,
            on_system=self._on_system,
            on_users=self._on_users,
            on_message=self._on_message,
            on_dh_update=self._on_dh_update,
            on_error=self._on_error,
            on_dh_offer=self._on_dh_offer,
        )

        try:
            self.client.connect()
            self.lbl_status.config(text="● Đã kết nối", fg=self.colors["success"])
            self._append_chat_line(
                "Đã kết nối tới máy chủ. Sẵn sàng trao đổi khóa và trò chuyện an toàn.",
                msg_type="system",
            )
        except Exception as e:
            self.lbl_status.config(text="● Kết nối thất bại", fg=self.colors["error"])
            messagebox.showerror("Lỗi kết nối", str(e))
            self.root.destroy()

    # ============================================================
    # CALLBACK TỪ CORE CLIENT
    # ============================================================

    def _on_system(self, text: str) -> None:
        self._append_chat_line(text, msg_type="system")

    def _on_error(self, text: str) -> None:
        messagebox.showerror("Lỗi", text)
        self._append_chat_line(f"Lỗi: {text}", msg_type="error")

    def _on_users(self, users: list[str]) -> None:
        self.user_listbox.delete(0, tk.END)
        for u in users:
            if u != self.username:
                self.user_listbox.insert(tk.END, u)

        count = len([u for u in users if u != self.username])
        self.lbl_user_count.config(text=str(count))

        if self.current_peer and self.current_peer not in users:
            # Peer hiện tại đã offline
            self.current_peer = None
            self._update_dh_visualizer(None)
            self.lbl_chat_with.config(text="Chọn một người dùng để bắt đầu trò chuyện")
            self.lbl_encryption_status.config(
                text="🔓 Chưa mã hóa", fg=self.colors["text_secondary"]
            )

    def _on_message(self, peer: str, text: str) -> None:
        self._append_chat_line(text, msg_type="peer", sender=peer)

    def _on_dh_update(self, peer: str, info: Dict[str, Any]) -> None:
        # Lưu thông tin DH để hiển thị
        self.dh_info[peer] = info

        # Nếu đang chat với peer này thì cập nhật panel + trạng thái
        if self.current_peer == peer:
            self._update_dh_visualizer(info)
            if info.get("shared_preview"):
                self.lbl_encryption_status.config(
                    text="🔒 Đã mã hóa", fg=self.colors["success"]
                )

        # Log hệ thống khi đã có shared key
        if info.get("shared_preview"):
            self._append_chat_line(
                f"Đã thiết lập kênh mã hóa với {peer}.", msg_type="system"
            )

    def _on_dh_offer(self, peer: str) -> None:
        # Chuyển sang thread UI
        self.root.after(0, self._handle_dh_offer_ui, peer)

    # ============================================================
    # HỖ TRỢ CHAT & UI
    # ============================================================

    def _append_chat_line(
        self,
        line: str,
        msg_type: str = "normal",
        sender: Optional[str] = None,
    ) -> None:
        ts = datetime.now().strftime("%H:%M")
        self.chat_text.configure(state="normal")

        if msg_type == "system":
            self.chat_text.insert("end", f"[{ts}] [Hệ thống] {line}\n", "system")
        elif msg_type == "error":
            self.chat_text.insert("end", f"[{ts}] [Lỗi] {line}\n", "error")
        elif msg_type == "peer" and sender:
            self.chat_text.insert("end", f"[{ts}] {sender}: {line}\n", "peer")
        elif msg_type == "me":
            self.chat_text.insert("end", f"[{ts}] Tôi: {line}\n", "me")
        else:
            self.chat_text.insert("end", f"[{ts}] {line}\n")

        self.chat_text.tag_config("system", foreground=self.colors["primary_light"])
        self.chat_text.tag_config("error", foreground=self.colors["error"])
        self.chat_text.tag_config("peer", foreground="#8e44ad")
        self.chat_text.tag_config("me", foreground=self.colors["success"])

        self.chat_text.see("end")
        self.chat_text.configure(state="disabled")

    def _refresh_users(self) -> None:
        if self.client:
            self.client.request_user_list()
            self._append_chat_line("Đang làm mới danh sách người dùng...", msg_type="system")

    def _on_user_selected(self, event=None) -> None:
        sel = self.user_listbox.curselection()
        if not sel:
            self.current_peer = None
            self._update_dh_visualizer(None)
            self.lbl_chat_with.config(text="Chọn một người dùng để bắt đầu trò chuyện")
            self.lbl_encryption_status.config(
                text="🔓 Chưa mã hóa", fg=self.colors["text_secondary"]
            )
            return

        idx = sel[0]
        peer = self.user_listbox.get(idx)
        self.current_peer = peer

        self.lbl_chat_with.config(text=f"Đang trò chuyện với {peer}")

        info = self.dh_info.get(peer)
        self._update_dh_visualizer(info)

        if info and info.get("shared_preview"):
            self.lbl_encryption_status.config(
                text="🔒 Đã mã hóa", fg=self.colors["success"]
            )
        else:
            self.lbl_encryption_status.config(
                text="🔓 Chưa mã hóa", fg=self.colors["text_secondary"]
            )

        # Giữ selection
        self.user_listbox.selection_clear(0, tk.END)
        self.user_listbox.selection_set(idx)
        self.user_listbox.see(idx)

    def _on_send_clicked(self, event=None) -> None:
        if not self.client:
            return
        if not self.current_peer:
            messagebox.showinfo(
                "Chọn người dùng",
                "Vui lòng chọn một người dùng trước khi gửi tin nhắn.",
            )
            return

        text = self.entry_message.get().strip()
        if not text:
            return

        # Chỉ cho phép gửi nếu đã có khóa bí mật chung
        info = self.dh_info.get(self.current_peer)
        if not info or not info.get("shared_preview"):
            msg = (
                "Chưa có khóa bí mật chung với người dùng này.\n"
                "Vui lòng thiết lập khóa Diffie–Hellman trước."
            )
            self._append_chat_line(msg, msg_type="error")
            messagebox.showerror("Chưa có khóa chung", msg)
            return

        # Nhờ core mã hóa + gửi; chỉ log 'Tôi:' khi send_chat trả về True
        ok = self.client.send_chat(self.current_peer, text)
        if ok:
            self.entry_message.delete(0, tk.END)
            self._append_chat_line(text, msg_type="me")

    # ============================================================
    # TRAO ĐỔI KHÓA DIFFIE–HELLMAN
    # ============================================================

    def _start_dh_with_selected(self) -> None:
        if not self.client or not self.current_peer:
            messagebox.showinfo(
                "Chọn người dùng",
                "Vui lòng chọn một người dùng trước khi thiết lập khóa.",
            )
            return

        peer = self.current_peer
        choice = messagebox.askyesnocancel(
            "Bắt tay khóa Diffie–Hellman",
            (
                f"Thiết lập khóa Diffie–Hellman với {peer}?\n\n"
                "Yes  → tự nhập số mũ bí mật a\n"
                "No   → để hệ thống sinh số mũ a ngẫu nhiên\n"
                "Cancel → hủy thao tác"
            ),
        )
        if choice is None:
            return

        if choice:  # người dùng tự nhập số mũ
            s = simpledialog.askstring(
                "Số mũ bí mật",
                "Nhập số mũ bí mật a (số nguyên dương):",
                parent=self.root,
            )
            if s is None:
                return
            try:
                a = int(s)
                if a <= 0:
                    raise ValueError
            except ValueError:
                messagebox.showerror(
                    "Giá trị không hợp lệ",
                    "Vui lòng nhập một số nguyên dương.",
                )
                return
            self.client.set_next_manual_exponent(a)
        else:
            self.client.set_next_manual_exponent(None)

        self.client.start_dh_with_peer(peer)
        self._append_chat_line(
            f"Bắt đầu bắt tay Diffie–Hellman với {peer}...", msg_type="system"
        )

    def _handle_dh_offer_ui(self, peer: str) -> None:
        if not self.client:
            return

        resp = messagebox.askyesnocancel(
            "Yêu cầu bắt tay khóa DH",
            (
                f"{peer} muốn thiết lập khóa Diffie–Hellman với bạn.\n\n"
                "Yes  → tự nhập số mũ bí mật b\n"
                "No   → để hệ thống sinh số mũ b ngẫu nhiên\n"
                "Cancel → từ chối yêu cầu"
            ),
        )
        if resp is None:
            return

        if resp:
            val = simpledialog.askinteger(
                "Số mũ bí mật của bạn",
                "Nhập số mũ bí mật b (số nguyên dương):",
                parent=self.root,
                minvalue=1,
            )
            if val is None:
                return
            manual_b = val
        else:
            manual_b = None

        self.client.accept_dh_offer(peer, manual_exponent=manual_b)
        self._append_chat_line(
            f"Đã chấp nhận yêu cầu bắt tay Diffie–Hellman từ {peer}...",
            msg_type="system",
        )

    # ============================================================
    # HÀM PHỤ
    # ============================================================

    def _shorten_value(self, value: Any, max_len: int = 40) -> str:
        s = str(value)
        return s if len(s) <= max_len else s[:max_len] + "..."

    def _update_dh_visualizer(self, info: Optional[Dict[str, Any]]) -> None:
        """Cập nhật panel 'Phiên hiện tại' theo trạng thái DH với peer hiện tại."""
        # Không có phiên
        if info is None:
            self.lbl_session_peer.config(text="Không có phiên nào đang hoạt động")
            for name in ["p_value", "g_value", "A_value", "B_value", "secret_value"]:
                getattr(self, f"lbl_{name}").config(
                    text="–", fg=self.colors["text_secondary"]
                )
            self.lbl_status_title.config(text="Trạng thái mã hóa")
            self.lbl_status_desc.config(text="Chưa có phiên mã hóa nào được thiết lập.")
            return

        peer = info.get("peer") or self.current_peer or "Không xác định"
        self.lbl_session_peer.config(text=f"Phiên với {peer}")

        # Tham số
        p = info.get("p")
        g = info.get("g")
        A = info.get("A")
        B = info.get("B")
        shared_preview = info.get("shared_preview")

        self.lbl_p_value.config(
            text=self._shorten_value(p) if p is not None else "–",
            fg=self.colors["text_secondary"],
        )
        self.lbl_g_value.config(
            text=str(g) if g is not None else "–",
            fg=self.colors["text_secondary"],
        )
        self.lbl_A_value.config(
            text=self._shorten_value(A) if A is not None else "–",
            fg=self.colors["text_secondary"],
        )
        self.lbl_B_value.config(
            text=self._shorten_value(B) if B is not None else "–",
            fg=self.colors["text_secondary"],
        )

        if shared_preview:
            self.lbl_secret_value.config(
                text=str(shared_preview),
                fg=self.colors["success"],
            )
            self.lbl_status_title.config(text="Đang mã hóa")
            self.lbl_status_desc.config(text=f"Đang sử dụng kênh mã hóa an toàn với {peer}.")
        else:
            self.lbl_secret_value.config(
                text="–",
                fg=self.colors["text_secondary"],
            )
            self.lbl_status_title.config(text="Trạng thái mã hóa")
            self.lbl_status_desc.config(text="Quá trình trao đổi khóa Diffie–Hellman đang diễn ra.")

    # ---------- LOGIC TẤN CÔNG MITM ----------

    def _run_mitm_attack_demo(self) -> None:
        """Tính toán các khóa trong kịch bản tấn công MITM trên DH thuần."""
        try:
            p = int(self.mitm_p_entry.get().strip())
            g = int(self.mitm_g_entry.get().strip())
            a = int(self.mitm_a_entry.get().strip())
            b = int(self.mitm_b_entry.get().strip())
            m1 = int(self.mitm_m1_entry.get().strip())
            m2 = int(self.mitm_m2_entry.get().strip())
        except ValueError:
            messagebox.showerror(
                "Dữ liệu không hợp lệ",
                "Vui lòng nhập các số nguyên cho p, g, a, b, m1, m2.",
            )
            return

        # Giá trị DH gốc
        A = pow(g, a, p)
        B = pow(g, b, p)
        A_to_bob = pow(g, m1, p)   # A' Mallory gửi cho Bob
        B_to_alice = pow(g, m2, p) # B' Mallory gửi cho Alice

        # Khóa mà mỗi phía thấy
        K_A = pow(B_to_alice, a, p)  # Khóa Alice (thực chất là khóa với Mallory)
        K_AM = pow(A, m2, p)         # Khóa Mallory–Alice
        K_B = pow(A_to_bob, b, p)    # Khóa Bob (thực chất là khóa với Mallory)
        K_MB = pow(B, m1, p)         # Khóa Mallory–Bob

        self.lbl_mitm_KA.config(text=str(K_A))
        self.lbl_mitm_Kam.config(text=str(K_AM))
        self.lbl_mitm_KB.config(text=str(K_B))
        self.lbl_mitm_Kmb.config(text=str(K_MB))

        if K_A == K_AM and K_B == K_MB and K_A != K_B:
            msg = (
                "Kết quả: Mallory đã thiết lập được hai khóa riêng biệt.\n"
                "• Alice dùng chung khóa với Mallory (K_A = K_AM).\n"
                "• Bob dùng chung khóa với Mallory (K_B = K_MB).\n"
                "• Khóa của Alice khác khóa của Bob (K_A ≠ K_B), "
                "vì vậy Alice và Bob KHÔNG còn chia sẻ cùng một khóa bí mật."
            )
        else:
            msg = (
                "Kết quả: các tham số hiện tại chưa tạo ra kịch bản MITM kinh điển "
                "(K_A = K_AM và K_B = K_MB nhưng K_A ≠ K_B).\n"
                "Hãy thử thay đổi giá trị m1, m2 để quan sát sự khác biệt."
            )
        self.lbl_mitm_plain_status.config(text=msg)

    # ============================================================
    # MAIN LOOP
    # ============================================================

    def run(self) -> None:
        self.root.mainloop()
