from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = bytes.fromhex('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff')
iv  = bytes.fromhex('0102030405060708090a0b0c0d0e0f10')
magic = bytes.fromhex('554d415f454e43525950544544')  # "UMAP_ENCRYPTED"

def decrypt_file(path: Path):
    data = path.read_bytes()
    if not data.startswith(magic):
        return

    data = data[len(magic):]  # strip header

    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        decrypted = unpad(cipher.decrypt(data), AES.block_size)
    except ValueError:
        decrypted = cipher.decrypt(data)

    out_path = path.with_suffix('.txt')
    out_path.write_bytes(decrypted)

def main():
    base = Path("trophy_case")
    for f in base.rglob("*.uma"):
        decrypt_file(f)

if __name__ == "__main__":
    main()
