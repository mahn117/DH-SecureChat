# src/client/core.py
from __future__ import annotations

import json
import socket
import threading
from typing import Any, Callable, Dict, Optional

from src.crypto import dh, aes

OnSystemCb = Callable[[str], None]
OnUsersCb = Callable[[list[str]], None]
OnMessageCb = Callable[[str, str], None]
OnDhUpdateCb = Callable[[str, Dict[str, Any]], None]
OnErrorCb = Callable[[str], None]
OnDhOfferCb = Callable[[str], None]


class SecureChatClient:
    def __init__(
        self,
        username: str,
        host: str,
        port: int,
        on_system: Optional[OnSystemCb] = None,
        on_users: Optional[OnUsersCb] = None,
        on_message: Optional[OnMessageCb] = None,
        on_dh_update: Optional[OnDhUpdateCb] = None,
        on_error: Optional[OnErrorCb] = None,
        on_dh_offer: Optional[OnDhOfferCb] = None,
    ) -> None:
        self.username = username
        self.host = host
        self.port = port

        # Callback UI / log
        self.on_system = on_system
        self.on_users = on_users
        self.on_message = on_message
        self.on_dh_update = on_dh_update
        self.on_error = on_error
        self.on_dh_offer = on_dh_offer

        self.sock: Optional[socket.socket] = None
        self.file = None
        self.running = False
        self.listener_thread: Optional[threading.Thread] = None

        # peer -> thông tin phiên Diffie–Hellman (DH)
        self.dh_sessions: Dict[str, Dict[str, Any]] = {}
        # peer -> gói dh_offer đang chờ phía người dùng này chấp nhận
        self.pending_dh_offers: Dict[str, dict] = {}

        # số mũ bí mật a do người dùng nhập cho lần bắt tay DH tiếp theo (None = sinh ngẫu nhiên)
        self.next_manual_exponent: Optional[int] = None

    # ========= KẾT NỐI / GỬI / NHẬN ========= #

    def connect(self) -> None:
        """Thiết lập kết nối TCP tới máy chủ và gửi gói HELLO."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        self.file = self.sock.makefile("r", encoding="utf-8")

        # Gửi gói HELLO để đăng ký username với server
        self._send_json({"type": "hello", "username": self.username})

        self.running = True
        self.listener_thread = threading.Thread(
            target=self._listen_loop,
            daemon=True,
        )
        self.listener_thread.start()

    def _send_json(self, obj: dict) -> None:
        """Gửi một object JSON dạng 1 dòng tới server."""
        if not self.sock:
            return
        data = (json.dumps(obj) + "\n").encode("utf-8")
        try:
            self.sock.sendall(data)
        except OSError as e:
            self.running = False
            if self.on_error:
                self.on_error(f"Lỗi khi gửi dữ liệu tới máy chủ: {e}")

    def _listen_loop(self) -> None:
        """Luồng nền lắng nghe các gói tin JSON từ máy chủ."""
        try:
            while self.running and self.file:
                line = self.file.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    # Bỏ qua gói tin không phải JSON hợp lệ
                    continue
                self._handle_message(msg)
        except OSError as e:
            if self.on_error:
                self.on_error(f"Mất kết nối tới máy chủ: {e}")
        finally:
            self.running = False
            if self.on_system:
                self.on_system("Đã mất kết nối tới máy chủ.")

    # ========= XỬ LÝ GÓI TIN TỪ MÁY CHỦ ========= #

    def _handle_message(self, msg: dict) -> None:
        msg_type = msg.get("type")

        if msg_type == "system":
            # Thông báo hệ thống từ server
            text = msg.get("text", "")
            if self.on_system:
                self.on_system(text)

        elif msg_type == "user_list":
            # Danh sách người dùng đang online
            users = msg.get("users", [])
            if self.on_users:
                self.on_users(users)

        elif msg_type == "chat":
            # Tin nhắn đã mã hóa AES từ peer
            frm = msg.get("from")
            cipher = msg.get("cipher")
            if not frm or cipher is None:
                return

            session = self.dh_sessions.get(frm)
            if not session or not session.get("shared_key"):
                # Nhận được tin mã hóa nhưng chưa có khóa chung
                if self.on_system:
                    self.on_system(
                        f"[Cảnh báo] Nhận tin nhắn từ {frm} nhưng chưa có khóa bí mật chung (DH)."
                    )
                return

            key = session["shared_key"]
            try:
                plaintext = aes.decrypt_message(key, cipher)
            except Exception:
                plaintext = "[Lỗi giải mã tin nhắn]"

            if self.on_message:
                self.on_message(frm, plaintext)

        elif msg_type == "dh_offer":
            # Lời mời bắt tay Diffie–Hellman từ peer
            peer = msg.get("from")
            if not peer:
                return

            self.pending_dh_offers[peer] = msg

            if self.on_dh_offer:
                # Giao cho GUI hỏi người dùng chấp nhận / từ chối
                self.on_dh_offer(peer)
            else:
                # Nếu không có GUI, mặc định chấp nhận với số mũ ngẫu nhiên
                self.accept_dh_offer(peer, manual_exponent=None)

        elif msg_type == "dh_answer":
            # Phản hồi bắt tay DH: phía B gửi khóa công khai B
            peer = msg.get("from")
            B = msg.get("B")
            if not peer or B is None:
                return

            session = self.dh_sessions.get(peer)
            if not session:
                return

            # Đây là phía khởi tạo (A)
            p = session["p"]
            a = session["a"]
            key, secret = dh.compute_shared_key(B, a, p)
            preview = dh.preview_from_key(key)

            session["B"] = B
            session["shared_key"] = key          # khóa bí mật chung dùng cho AES
            session["secret"] = secret           # giá trị bí mật DH đầy đủ (nếu cần)
            session["shared_preview"] = preview  # chuỗi rút gọn để hiển thị

            self._emit_dh_update(peer)

            if self.on_system:
                self.on_system(
                    f"Đã hoàn tất bắt tay Diffie–Hellman với {peer}. Khóa bí mật chung đã được thiết lập."
                )

    # ========= DANH SÁCH NGƯỜI DÙNG ========= #

    def request_user_list(self) -> None:
        """Yêu cầu máy chủ gửi lại danh sách người dùng đang online."""
        self._send_json({"type": "user_list_request"})

    # ========= DIFFIE–HELLMAN ========= #

    def set_next_manual_exponent(self, value: Optional[int]) -> None:
        """
        Ghi nhớ số mũ bí mật a (hoặc None) cho lần bắt tay DH
        tiếp theo do phía người dùng này khởi tạo.
        """
        self.next_manual_exponent = value

    def start_dh_with_peer(self, peer: str) -> None:
        """
        Khởi tạo bắt tay Diffie–Hellman với peer (vai A).
        Có thể sử dụng số mũ a do người dùng nhập trước đó.
        """
        if not self.sock:
            if self.on_error:
                self.on_error("Chưa kết nối tới máy chủ.")
            return

        if peer == self.username:
            if self.on_error:
                self.on_error("Không thể thiết lập khóa với chính tài khoản của bạn.")
            return

        # Sinh tham số p, g chuẩn dùng chung cho DH
        p, g = dh.get_parameters()
        exponent = self.next_manual_exponent
        # Dùng xong thì reset, tránh ảnh hưởng các lần sau
        self.next_manual_exponent = None

        # Tạo cặp khóa DH (a, A = g^a mod p)
        kp = dh.generate_keypair(p=p, g=g, exponent=exponent)
        a = kp["private"]
        A = kp["public"]

        # Lưu trạng thái phiên DH với peer này
        self.dh_sessions[peer] = {
            "role": "initiator",
            "p": p,
            "g": g,
            "a": a,
            "A": A,
            "B": None,
            "shared_key": None,
            "secret": None,
            "shared_preview": None,
        }

        # Gửi lời mời bắt tay DH tới peer
        msg = {
            "type": "dh_offer",
            "from": self.username,
            "to": peer,
            "p": p,
            "g": g,
            "A": A,
        }
        self._send_json(msg)

        # Thông báo cho GUI để cập nhật panel Current Session
        self._emit_dh_update(peer)

        if self.on_system:
            if exponent is None:
                self.on_system(
                    f"Bắt đầu bắt tay Diffie–Hellman với {peer} (số mũ bí mật sinh ngẫu nhiên)."
                )
            else:
                self.on_system(
                    f"Bắt đầu bắt tay Diffie–Hellman với {peer} (a = {exponent} do người dùng nhập)."
                )

    def accept_dh_offer(self, peer: str, manual_exponent: Optional[int]) -> None:
        """
        Phía B chấp nhận lời mời bắt tay Diffie–Hellman từ peer (vai A),
        có thể dùng số mũ bí mật b do người dùng nhập.
        """
        offer = self.pending_dh_offers.pop(peer, None)
        if not offer:
            if self.on_error:
                self.on_error("Không tìm thấy lời mời Diffie–Hellman tương ứng.")
            return

        p = offer["p"]
        g = offer["g"]
        A = offer["A"]

        # Chọn b: do người dùng nhập hoặc sinh ngẫu nhiên hợp lệ
        if manual_exponent is None:
            b = dh.generate_private_exponent(p)
        else:
            b = manual_exponent

        B = pow(g, b, p)
        key, secret = dh.compute_shared_key(A, b, p)
        preview = dh.preview_from_key(key)

        # Lưu trạng thái phiên DH với peer này
        self.dh_sessions[peer] = {
            "role": "responder",
            "p": p,
            "g": g,
            "a": None,  # phía B không cần lưu a
            "A": A,
            "b": b,
            "B": B,
            "shared_key": key,
            "secret": secret,
            "shared_preview": preview,
        }

        # Gửi phản hồi DH (khóa công khai B) về cho phía khởi tạo
        msg = {
            "type": "dh_answer",
            "from": self.username,
            "to": peer,
            "B": B,
        }
        self._send_json(msg)

        # Cập nhật giao diện
        self._emit_dh_update(peer)

        if self.on_system:
            if manual_exponent is None:
                self.on_system(
                    f"Đã chấp nhận bắt tay Diffie–Hellman từ {peer} (số mũ bí mật sinh ngẫu nhiên)."
                )
            else:
                self.on_system(
                    f"Đã chấp nhận bắt tay Diffie–Hellman từ {peer} (b = {manual_exponent} do người dùng nhập)."
                )

    def _emit_dh_update(self, peer: str) -> None:
        """Đẩy thông tin phiên DH hiện tại cho GUI để cập nhật panel hiển thị."""
        if not self.on_dh_update:
            return
        session = self.dh_sessions.get(peer)
        if not session:
            return
        info = {
            "peer": peer,
            "role": session.get("role"),
            "p": session.get("p"),
            "g": session.get("g"),
            "A": session.get("A"),
            "B": session.get("B"),
            "shared_preview": session.get("shared_preview"),
        }
        self.on_dh_update(peer, info)

    # ========= CHAT (AES) ========= #

    def send_chat(self, peer: str, text: str) -> bool:
        """
        Mã hóa và gửi tin nhắn văn bản tới `peer` bằng khóa bí mật chung (AES).

        Trả về:
            True  - nếu tin nhắn đã được xếp hàng/gửi thành công.
            False - nếu chưa có khóa chung hoặc các điều kiện tiền kiểm khác không thỏa.
        """
        session = self.dh_sessions.get(peer)
        if not session or not session.get("shared_key"):
            if self.on_error:
                self.on_error(
                    "Chưa có khóa bí mật chung với người dùng này. "
                    "Vui lòng thực hiện bắt tay Diffie–Hellman trước."
                )
            return False

        key = session["shared_key"]
        cipher = aes.encrypt_message(key, text)
        msg = {
            "type": "chat",
            "from": self.username,
            "to": peer,
            "cipher": cipher,
        }
        self._send_json(msg)
        return True
