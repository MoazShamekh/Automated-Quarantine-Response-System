import time
import sys

def main():
    print("Starting countdown...")
    for i in range(3, 0, -1):
        print(i)
        time.sleep(1)

    print("BOOOOOOOOOOOOOOOOOOOOOOOOOOM!")
    time.sleep(3)

if __name__ == "__main__":
    main()
