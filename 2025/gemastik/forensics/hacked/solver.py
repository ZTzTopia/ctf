from pwn import *

r = remote('165.232.133.53', 9082)

r.sendline(b'https://github.com/walawe1337-oss/simple-python-server')
r.sendline(b'11e128c2bf2f82f4e966a0ec2ff072bb')
r.sendline(b'this_is_my_secret_aes_256_key!!!:abcdef1234567890')
r.sendline(b'165.232.133.53:12311')
r.sendline(b'echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICUHM+DTrehpFANzpOzDPUJi1DYaK1xwMpMLz1QqwxJ0 kali@kali" >> /root/.ssh/authorized_keys')
r.sendline(b'T1098.004')

r.interactive()
