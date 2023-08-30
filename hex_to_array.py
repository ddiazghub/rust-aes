import sys

WORD_SIZE = 8

def hex_to_array(hex: str):
    words = [hex[i:i + WORD_SIZE] for i in range(0, len(hex), WORD_SIZE)]
    print("[")

    for word in words:
        bytes = [f"0x{word[i: i + 2]}" for i in range(0, len(word), 2)]
        print(", ".join(bytes), end=",\n")

    print("]")

if __name__ == "__main__":
    hex_to_array(sys.argv[1])
