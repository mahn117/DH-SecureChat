# src/server/main.py
from .core import ChatServer


def main():
    server = ChatServer(host="127.0.0.1", port=5000)
    server.start()


if __name__ == "__main__":
    main()
