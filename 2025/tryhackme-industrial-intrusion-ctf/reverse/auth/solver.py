from pwn import *

context.binary = './auth'
context.log_level = 'debug'

# r = process('./auth')
r = remote('10.10.57.42', 9005)

def transform(a1, a2):
    result = bytearray(a1)
    for i in range(a2):
        result[i] ^= 0x55
    return bytes(result)

code = bytes.fromhex('EFCDAB8967452301')[::-1]
decrypted_code = transform(code, 8)

log.info(f'Decrypted code: {decrypted_code.hex()}')
r.sendline(decrypted_code)
r.interactive()
