# src/server/core.py
"""
ChatServer cho DH-SecureChat (newline-delimited JSON)

Chức năng:
- Nhận HELLO (type="hello", username="...") để đăng ký username
- Broadcast danh sách user online cho TẤT CẢ client mỗi khi có thay đổi
- Relay các gói tin có trường "to" giữa các client:
    + type = "chat"      : tin nhắn (ciphertext) đã mã hóa
    + type = "dh_offer"  : lời mời bắt tay Diffie–Hellman
    + type = "dh_answer" : trả lời bắt tay Diffie–Hellman
    + ...

Server KHÔNG giải mã nội dung.
"""

# src/server/core.py
from __future__ import annotations

import json
import socket
import threading
from typing import Dict, Tuple, Optional, List


class ChatServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 5000) -> None:
        self.host = host
        self.port = port

        # username -> socket
        self.clients: Dict[str, socket.socket] = {}
        self.lock = threading.Lock()
        self.sock: Optional[socket.socket] = None

    # ========= JSON helpers ========= #

    def _send_json(self, sock: socket.socket, obj: dict) -> None:
        data = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
        sock.sendall(data)

    def _recv_json(self, f) -> Optional[dict]:
        line = f.readline()
        if not line:
            return None
        line = line.strip()
        if not line:
            return None
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return None



    # ========= User list ========= #

    def _send_user_list_to_one(self, username: str, sock: socket.socket) -> None:
        with self.lock:
            users = list(self.clients.keys())
        others = [u for u in users if u != username]
        self._send_json(sock, {"type": "user_list", "users": others})

    def _broadcast_user_list(self) -> None:
        with self.lock:
            items = list(self.clients.items())

        dead: List[str] = []
        for username, sock in items:
            try:
                self._send_user_list_to_one(username, sock)
            except OSError:
                dead.append(username)

        if dead:
            with self.lock:
                for u in dead:
                    s = self.clients.pop(u, None)
                    if s:
                        try:
                            s.close()
                        except OSError:
                            pass

    # ========= Logging ========= #

    def _extract_public_key_preview(self, msg: dict) -> str:
        """
        Cố gắng lấy ra các trường liên quan DH public key để log.
        Tùy client, field có thể là: A/B, public, public_key, pub, offer/answer payload...
        """
        candidates = [
            "A", "B", "public", "public_key", "pub", "dh_public", "dh_pub",
            "client_pub", "peer_pub", "gx", "gy"
        ]

        found = []
        for k in candidates:
            if k in msg:
                v = msg.get(k)
                if v is None:
                    continue
                s = str(v)
                if len(s) > 120:
                    s = s[:120] + "..."
                found.append(f"{k}={s}")

        # Một số client có thể nhét vào payload con
        for nested_key in ("data", "payload", "body", "offer", "answer"):
            nested = msg.get(nested_key)
            if isinstance(nested, dict):
                for k in candidates:
                    if k in nested:
                        v = nested.get(k)
                        if v is None:
                            continue
                        s = str(v)
                        if len(s) > 120:
                            s = s[:120] + "..."
                        found.append(f"{nested_key}.{k}={s}")

        return " | ".join(found)

    def _log_packet(self, stage: str, msg: dict) -> None:
        msg_type = msg.get("type")
        fr = msg.get("from")
        to = msg.get("to")

        if msg_type == "chat":
            cipher = msg.get("cipher") or msg.get("ciphertext") or ""
            print(
                f"[{stage}][CHAT] from={fr} to={to} "
                f"cipher_preview={str(cipher)[:80]}..."
            )
            return

        if msg_type in ("dh_offer", "dh_answer"):
            pk_preview = self._extract_public_key_preview(msg)
            print(f"[{stage}][{msg_type.upper()}] from={fr} to={to}")
            if pk_preview:
                print(f"    [PUBLIC-KEY] {pk_preview}")
            return

        if to is not None:
            print(f"[{stage}][{msg_type}] from={fr} to={to}")
        else:
            print(f"[{stage}][{msg_type}]")

    # ========= Client handler ========= #

    def _handle_client(self, sock: socket.socket, addr: Tuple[str, int]) -> None:
        username: Optional[str] = None
        f = sock.makefile("r", encoding="utf-8")

        try:
            # 1) hello
            hello = self._recv_json(f)
            if not hello or hello.get("type") != "hello":
                try:
                    sock.close()
                except OSError:
                    pass
                return

            username = str(hello.get("username") or "").strip()
            if not username:
                try:
                    self._send_json(sock, {"type": "system", "text": "Missing username"})
                except OSError:
                    pass
                try:
                    sock.close()
                except OSError:
                    pass
                return

            # 2) register
            with self.lock:
                old = self.clients.get(username)
                if old is not None and old is not sock:
                    try:
                        old.close()
                    except OSError:
                        pass
                self.clients[username] = sock

            print(f"[INFO] {username} connected from {addr}")
            self._broadcast_user_list()

            # 3) loop
            while True:
                msg = self._recv_json(f)
                if msg is None:
                    break

                # log recv
                self._log_packet("RECV", msg)

                msg_type = msg.get("type")

                if msg_type == "user_list_request":
                    try:
                        self._send_user_list_to_one(username, sock)
                    except OSError:
                        break
                    continue

                # relay: có trường "to"
                if "to" in msg:
                    to_user = msg.get("to")
                    if not to_user:
                        continue

                    with self.lock:
                        target_sock = self.clients.get(to_user)

                    if not target_sock:
                        try:
                            self._send_json(
                                sock,
                                {"type": "system", "text": f"User '{to_user}' is offline."},
                            )
                        except OSError:
                            pass
                        continue

                    try:
                        self._send_json(target_sock, msg)
                        self._log_packet("FWD", msg)
                    except OSError:
                        with self.lock:
                            dead_sock = self.clients.pop(to_user, None)
                        if dead_sock:
                            try:
                                dead_sock.close()
                            except OSError:
                                pass
                        self._broadcast_user_list()

        finally:
            if username is not None:
                with self.lock:
                    if self.clients.get(username) is sock:
                        self.clients.pop(username, None)

                try:
                    sock.close()
                except OSError:
                    pass

                print(f"[INFO] {username} disconnected")
                self._broadcast_user_list()
            else:
                try:
                    sock.close()
                except OSError:
                    pass

    # ========= Server loop ========= #

    def start(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(50)

        print(f"[INFO] ChatServer listening on {self.host}:{self.port}")

        try:
            while True:
                client_sock, addr = self.sock.accept()
                t = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, addr),
                    daemon=True,
                )
                t.start()
        except KeyboardInterrupt:
            print("\n[INFO] Server shutting down...")
        finally:
            with self.lock:
                items = list(self.clients.items())
                self.clients.clear()

            for _, s in items:
                try:
                    s.close()
                except OSError:
                    pass

            if self.sock:
                try:
                    self.sock.close()
                except OSError:
                    pass
                self.sock = None
