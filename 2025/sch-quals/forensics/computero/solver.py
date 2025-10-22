from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import os

KEY = b'sacred_key_32145'

def decrypt_file(infile, outfile):
    with open(infile, 'rb') as f:
        fake_iv = b'\x00' * 16
        enc = f.read()

    cipher = AES.new(KEY, AES.MODE_CBC, fake_iv)
    data = unpad(cipher.decrypt(enc), AES.block_size)

    fixed = bytearray(data)
    
    header = bytes([
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 
    ])
    fixed[0:16] = header

    with open(outfile, 'wb') as f:
        f.write(fixed)


    print(f"Decrypted {infile} → {outfile}")

# get all files from Documents folder and decrypt
folder = 'Documents/'

for inp in os.listdir(folder):
    if inp.endswith('.enc'):
        decrypt_file(os.path.join(folder, inp), os.path.join('out', inp[:-4]))
