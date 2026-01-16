# examples/attack_compare.py
from src.attacks.mitm_demo import run_mitm_demo
from src.attacks.mitm_patch import run_mitm_protected_demo


def main():
    print("=== DH thuần (bị MITM tấn công thành công) ===")
    run_mitm_demo()

    print("\n\n==============================================")
    print("=== DH + HMAC (MITM bị phát hiện, kết nối hủy) ===")
    run_mitm_protected_demo()


if __name__ == "__main__":
    main()
