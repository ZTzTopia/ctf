from pwn import *

r = remote('165.232.133.53', 9081)

r.sendline(b'TrevorC2')
r.sendline(b'aewfoijdc887xc6qwj21t')
r.sendline(b'whoami')
r.sendline(b'http://192.168.56.102:8888/m')
r.sendline(b'AES')
r.sendline(b'7aeaef7351e88b7a')
r.sendline(b'b2195af3d80ec529')
r.sendline(b'remove flag hahaha')
r.sendline(b'Walawe1337!!@@')

r.interactive()
