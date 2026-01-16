# src/client/main.py
import tkinter as tk
from .gui import ChatGUI


def main():
    root = tk.Tk()
    app = ChatGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
