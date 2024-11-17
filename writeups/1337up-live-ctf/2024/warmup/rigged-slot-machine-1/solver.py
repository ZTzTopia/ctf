from pwn import *
import ctypes
import time

libc = ctypes.CDLL("libc.so.6")

context.log_level = 'DEBUG'

while True:
    r = remote('riggedslot1.ctf.intigriti.io', 1332)

    libc.srand(libc.time(0))
    balance = 100

    # r.recvuntil(b'Enter your bet amount (up to $100 per spin): ')

    for _ in range(1152):
        rand = libc.rand()
        rand = rand % 100
        multiplier = 0

        if rand == 0:
            multiplier = 100
        elif rand < 10:
            multiplier = 5
        elif rand < 0xf:
            multiplier = 3
        elif rand < 0x14:
            multiplier = 2
        elif rand < 0x1e:
            multiplier = 1
        else:
            multiplier = 0

        bet = balance
        if multiplier > 0:
            if balance > 100:
                bet = 100
        else:
            bet = 1

        balance += bet * multiplier - bet
        r.sendline(str(bet).encode())

    if b'INTIGRITI{' in r.recvall():
        r.interactive()
        break

    time.sleep(0.1)
    r.close()
