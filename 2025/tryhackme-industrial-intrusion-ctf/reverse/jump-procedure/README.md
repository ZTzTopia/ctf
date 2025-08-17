---
title: "Jump Procedure"
categories: Reverse Engineering
tags: 
draft: false
completedDuringEvent: true
submitted: true
points: 90
solves: -1
flag: THM{REDACTED}
---
> ZeroTrace traces erratic branches through a tangle of industrial routines. Each calculated jump peels back another layer of the control logic.

---

The binary provided in this challenge acts as a command execution dispatcher. It takes user input and—based on certain conditions—jumps to dynamically calculated memory addresses to execute logic that ultimately leads to revealing the flag. To successfully execute the final command (`system("cat flag.txt")`), we must understand how the server handles commands and how it uses metadata (input values) to navigate its internal logic.

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  __int64 v4; // [rsp+28h] [rbp-28h]

  printf("Process ID: ");
  fflush(_bss_start);
  v4 = read_long();
  printf("Skip bytes proc: ");
  fflush(_bss_start);
  read_long();
  printf("Process bound: ");
  fflush(_bss_start);
  read_long();
  __asm { jmp     rax }
  return result;
}
```

This function reads three user inputs: a *Process ID*, a *Skip Bytes* value, and a *Process Bound*. Finally, it jumps to the address stored in `rax`. This jump forms the core dispatch mechanism of the binary.

```
.text:00000000000012E8                 mov     [rbp+var_18], rax
.text:00000000000012EC                 mov     rax, [rbp+var_20]
.text:00000000000012F0                 mov     [rbp+var_10], rax
.text:00000000000012F4                 mov     [rbp+var_2C], 1
.text:00000000000012FB                 mov     rsi, [rbp+var_28]
.text:00000000000012FF                 mov     rdi, [rbp+var_10]
.text:0000000000001303                 mov     r8, [rbp+var_18]
.text:0000000000001307                 mov     rcx, rsi
.text:000000000000130A                 mov     rdx, 0CCCCCCCCCCCCCCCDh
.text:0000000000001314                 mov     rax, rcx
.text:0000000000001317                 mul     rdx
.text:000000000000131A                 shr     rdx, 4
.text:000000000000131E                 mov     rax, rdx
.text:0000000000001321                 shl     rax, 2
.text:0000000000001325                 add     rax, rdx
.text:0000000000001328                 shl     rax, 2
.text:000000000000132C                 sub     rcx, rax
.text:000000000000132F                 mov     rdx, rcx
.text:0000000000001332                 mov     r10, rdx
.text:0000000000001335                 lea     rax, next_label
.text:000000000000133C                 add     rax, r10
.text:000000000000133F                 jmp     rax
```

This math calculates the effective jump target as `next_label + (skip % 20)`. Hence, the `Skip Bytes` input acts as an offset into a jump table beginning at `next_label`.

```c
__int64 __fastcall next_label(unsigned __int64 a1)
{
  __int64 v1; // rbp

  *(_DWORD *)(v1 - 44) *= 2;
  *(_DWORD *)(v1 - 44) *= 2;
  *(_DWORD *)(v1 - 44) *= 2;
  *(_DWORD *)(v1 - 44) *= 2;
  *(_DWORD *)(v1 - 44) *= 2;
  *(_DWORD *)(v1 - 44) *= 2;
  *(_DWORD *)(v1 - 44) *= 2;
  return ((__int64 (__fastcall *)())((char *)next_label2 + a1 % 0x96))();
}
```

This function intensively multiplies a stack variable by 2 repeatedly, then dispatches again to `next_label2`, offset by `a1 % 150`.

```c
__int64 __fastcall next_label2(__int64 a1, __int64 a2, __int64 a3, __int64 a4, unsigned __int64 a5)
{
  __int64 v5; // rbp

  *(_DWORD *)(v5 - 44) += 2;
  *(_DWORD *)(v5 - 44) *= 4;
  *(_DWORD *)(v5 - 44) += 2;
  *(_DWORD *)(v5 - 44) *= 4;
  *(_DWORD *)(v5 - 44) += 2;
  *(_DWORD *)(v5 - 44) *= 4;
  *(_DWORD *)(v5 - 44) += 2;
  *(_DWORD *)(v5 - 44) *= 4;
  *(_DWORD *)(v5 - 44) += 2;
  *(_DWORD *)(v5 - 44) *= 4;
  *(_DWORD *)(v5 - 44) += 2;
  *(_DWORD *)(v5 - 44) *= 4;
  *(_DWORD *)(v5 - 44) += 2;
  *(_DWORD *)(v5 - 44) *= 4;
  *(_DWORD *)(v5 - 44) += 2;
  *(_DWORD *)(v5 - 44) *= 4;
  *(_DWORD *)(v5 - 44) += 2;
  *(_DWORD *)(v5 - 44) *= 4;
  *(_DWORD *)(v5 - 44) += 2;
  *(_DWORD *)(v5 - 44) *= 4;
  *(_DWORD *)(v5 - 44) += 2;
  *(_DWORD *)(v5 - 44) *= 4;
  *(_DWORD *)(v5 - 44) += 2;
  *(_DWORD *)(v5 - 44) *= 4;
  *(_DWORD *)(v5 - 44) += 2;
  *(_DWORD *)(v5 - 44) *= 4;
  *(_DWORD *)(v5 - 44) += 2;
  *(_DWORD *)(v5 - 44) *= 4;
  *(_DWORD *)(v5 - 44) += 2;
  *(_DWORD *)(v5 - 44) *= 4;
  return ((__int64 (__fastcall *)())((char *)next_label3 + a5 - 240 * (a5 / 0xC8)))();
}
```

This continues to manipulate the same memory location, applying a mix of addition and multiplication. The final jump is to `next_label3`, based on modular arithmetic (`a5 % 200`).

```c
__int64 __fastcall next_label3()
{
  __int64 v0; // rbp

  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  ++*(_DWORD *)(v0 - 44);
  if ( ++*(_DWORD *)(v0 - 44) == 1337 )
    system("cat flag.txt");
  else
    printf("Procedure Error");
  return 0LL;
}
```

Finally, if the resulting value equals **1337**, the program prints the flag. Otherwise, it reports failure.

To reach the flag-revealing code, we must manipulate our inputs (`pid`, `skip`, `bound`) to precisely control the memory and control flow so that the variable at `[rbp - 44]` equals **1337** at the `next_label3()` check.

You can approach this in two ways:

1. Manual Analysis with GDB
   Set breakpoints at the start of each `next_label` function, observe how the input values manipulate memory, and adjust accordingly.
2. Brute Force
   Use the following Python script to exhaustively test all combinations:

```py
from pwn import *

BINARY = './jmpproc'

context.binary = BINARY
# context.log_level = 'debug'

def final_acc(pid, skip, bound):
    out = b'Procedure Error'
    try:
        p = process(BINARY)
        p.sendlineafter(b'Process ID: ', str(pid).encode())
        p.sendlineafter(b'Skip bytes proc: ', str(skip).encode())
        p.sendlineafter(b'Process bound: ', str(bound).encode())
        out = p.recvline().strip()
    except Exception as e:
        log.failure(f"Error occurred: {e}")

    p.close()
    return out != b'Procedure Error'

for pid in range(20):
    for skip in range(150):
        for bound in range(240):
            log.info(f'Testing PID: {pid}, Skip: {skip}, Bound: {bound}')
            if final_acc(pid, skip, bound):
                print(pid, skip, bound)
                break
```
