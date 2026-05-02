import ctypes

def main():
    ctypes.windll.user32.MessageBoxW(
        0,
        "⚠ Suspicious activity detected!\nThis is a demo warning.",
        "Security Warning",
        0x10
    )

if __name__ == "__main__":
    main()
