cipher_text = "60 08 71 1b 28 15 79 17 7c 36 5e 37 14 3e 4a 07 45 79 41 11 1b 19 57 2a 02 3a 46 7e 0a 77 04 07 5a 2c 51 25 49 34 6f 3a 53 2e 59 11 0e 2e 03 36 4f"
key = "2M2NzF0X"

def xor_decrypt(cipher_text, key):
    cipher_bytes = bytes.fromhex(cipher_text)
    key_bytes = key.encode('utf-8')
    decrypted_bytes = bytearray()
    
    for i in range(len(cipher_bytes)):
        decrypted_bytes.append(cipher_bytes[i] ^ key_bytes[i % len(key_bytes)])
    
    return decrypted_bytes.decode('utf-8')

print(f'Flag: {xor_decrypt(cipher_text, key)}')
