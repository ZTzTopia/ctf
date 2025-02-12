def mod_inverse(a):
    for i in range(256):
        if (a * i) % 256 == 1:
            return i

def affine_decrypt(a, b, x):
    return mod_inverse(a) * (x - b) % 256

encrypted_bytes = bytes.fromhex("abf6c8abb5daabc8ab69d7846def17b19c6dae843a6dd7e1b1173ae16db184e0b86dd7c5843ae8dee15f")

xor_value = 51
multiplier = 9
increment = 7

decrypted_bytes = [affine_decrypt(multiplier, increment, byte ^ xor_value) for byte in encrypted_bytes]
print(f'Flag: {bytes(decrypted_bytes).decode()}')
