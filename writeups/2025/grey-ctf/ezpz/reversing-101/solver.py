from pwn import *
from Crypto.Cipher import ARC4

context.log_level = 'debug'

r = remote('challs.nusgreyhats.org', 33000)

r.sendlineafter(b':', b'0x402db6')
r.sendlineafter(b':', b'strlen')
r.sendlineafter(b':', b'15')
r.sendlineafter(b':', b'0xc1de1494171d9e2f')
r.sendlineafter(b':', b'rc4')

def custom_rc4(data: bytes, key: int) -> bytes:
    key_bytes = key.to_bytes(8, byteorder='little')  # Matches (unsigned __int64) layout

    # Initialize state array S (like RC4's S-box)
    S = list(range(256))
    j = 0

    # Key Scheduling Algorithm (customized)
    for i in range(256):
        j = (S[i] + j + key_bytes[i % 8]) % 256
        S[i], S[j] = S[j], S[i]

    # Pseudo-Random Generation Algorithm
    i = j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        t = (S[i] + S[j]) % 256
        result.append(byte ^ S[t])

    return bytes(result)


key_int = 0xc1de1494171d9e2f
# key_bytes = key_int.to_bytes(8, byteorder='big')
# cipher = ARC4.new(key_bytes)
# plaintext = cipher.decrypt(b'\xD1\x58\x15\x8A\xEE\xB5\xBB\x52\x0C\x6B\xA4\xAB\x6D\x7D\xB7')
ciphertext = b'\xD1\x58\x15\x8A\xEE\xB5\xBB\x52\x0C\x6B\xA4\xAB\x6D\x7D\xB7'
plaintext = custom_rc4(ciphertext, key_int)
log.info(f'Plaintext: {plaintext}')

r.sendlineafter(b':', plaintext)

r.interactive()
