ciphertext = "23a326c27bee9b40885df97007aa4dbe410e93"
ciphertext = bytes.fromhex(ciphertext)
key = "Awesome!"
carry = 0

flag = []
for i, c in enumerate(ciphertext):
    c ^= ord(key[i % len(key)])
    c -= carry
    c %= 256
    flag.append(c)
    carry += c
    carry %= 256

print(f'Flag: {bytes(flag).decode()}')
