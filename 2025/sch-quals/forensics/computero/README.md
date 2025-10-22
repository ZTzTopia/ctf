---
title: Computero
categories: Forensics
authors: rgx26
tags: 
draft: false
completedDuringEvent: true
submitted: true
points: 323
solves: 19
flags: SCH25{fl4ggknyA_In111_y4h_B4ng_Cr0c0dilldildilololo}
---

> Seorang hacker berhasil mengencrypt seluruh dokumen milik rey. Padahal salah satu dokumen tersebut memiliki pesan yang sangat penting. Untungnya, hacker tidak membuang permanen jejak-jejak penyerangannya. Bantulah rey mendapatkan pesan pentingnya kembali.
>
> https://drive.google.com/file/d/11EIBwPIyQ0UA3s3_1xNAGHdN4zZFNTk-/view?usp=sharing pass: cmV5YWRhbGFocGVtYnVhdHNvYWxpbml5YW5nc2VkYW5nZGl0b250b25vbGVobGF2YWRvcmUxMjM=

---

In this problem, we are given an E01 file named `Hacked.E01`. An E01 file is a forensic image format commonly used to store bit-by-bit copies of digital storage media.

Here's how to mount the E01 file on a Linux system:

```sh
2025  file Computero/Hacked/Hacked.E01
2030  mmls Computero/Hacked/Hacked.E01
2040  ewfinfo Hacked.E01
2063  sudo ewfmount Hacked.E01 /mnt/ewf
2092  sudo ntfs-3g -o ro /mnt/ewf/ewf1 /mnt/image
```

Once mounted, we can view the contents of the image in the `/mnt/image` directory. It turns out to be a NTFS directory structure of `C:\Users\<username>` on a Windows system. After exploring the directory's contents, we find a recently deleted file with an executable extension in the Recycle Bin (`$Recycle.Bin/S-1-5-21-.../.../<random>.exe`).

This executable file is a Python executable that has been converted into an executable using PyInstaller. We can extract the original Python code from this executable using `pyinstxtractor.py`. After extracting, we find a Base64-encoded string that has been compressed and reversed. After attempting to decode it, we find that it contains a Base64-encoded string that has been compressed and reversed. We can create a Python script to decode it repeatedly until we get the original Python code. Here is the Python script used to decode the string:

```py
import base64
import re
import zlib

data = b"""
exec((_)(b'=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'))
"""

while True:
    try:
        m = re.search(rb"b(['\"])(.*?)\1", data, re.DOTALL)
        if not m:
            break

        data = m.group(2)
        data = base64.b64decode(data[::-1])
        data = zlib.decompress(data)

        if b'exec' not in data:
            print(data.decode())
    except Exception:
        break
```

The decoded result of the script above is the following Python code:

```py
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
from Cryptodome.Random import get_random_bytes
import os

key = b'sacred_key_32145'
file_in = 'Screenshot a.png'
file_out = 'encrypted_image.png.enc'

def encrypt_file(input_file, output_file, encryption_key):
    try:
        with open(input_file, 'rb') as f_in:
            plaintext = f_in.read()

        iv = get_random_bytes(16)
        cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        with open(output_file, 'wb') as f_out:
            f_out.write(ciphertext)
        
        print(f"File '{input_file}' encrypted to '{output_file}' successfully.")

    except FileNotFoundError:
        print(f"Error: Input file not found at '{input_file}'")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == '__main__':
    encrypt_file(file_in, file_out, key)
```

The code above is a Python program that encrypts an image file (`Screenshot a.png`) using the AES algorithm in CBC mode. The encryption key used is `sacred_key_32145`. The resulting encryption is stored in a new file named `encrypted_image.png.enc`.

To decrypt the file, we can create a new Python script similar to the code above, but using the decryption mode. Since the IV used for encryption is not stored in the encrypted file, we will use a dummy IV (16 bytes of zeros) to decrypt the file. However, after decryption, we need to repair the PNG file header, which was corrupted during the encryption process.

Here is the Python script to decrypt the file:

```py
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
```

Kita akan menemukan flag pada file `Screenshot (224).png` yang telah didekripsi:

![alt text](Screenshot%20(224).png)
