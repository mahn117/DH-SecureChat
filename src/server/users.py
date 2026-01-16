# src/server/users.py
"""
Quản lý danh sách user đang online trên server.
"""

class UserRegistry:
    def __init__(self):
        # username -> {"conn": socket, "dh_public": str}
        self._clients = {}

    def add(self, username, conn, dh_public):
        self._clients[username] = {"conn": conn, "dh_public": dh_public}

    def remove(self, username):
        if username in self._clients:
            del self._clients[username]

    def get_conn(self, username):
        info = self._clients.get(username)
        return info["conn"] if info else None

    def get_public(self, username):
        info = self._clients.get(username)
        return info["dh_public"] if info else None

    def list_users(self):
        return sorted(self._clients.keys())
