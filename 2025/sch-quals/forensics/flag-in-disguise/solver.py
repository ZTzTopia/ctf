import binascii
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad

password = 'ouk4kaw4i1inschits25'
ct_hex = '3fbe12d0608c4fedde2d9359013f9ed6db7cc8a160fed1acb6b14de7eafcaa1b7780d06af4b2859e5c7755ed35bde08f9cdd3a06568199119554a28461ffb475'

ct = binascii.unhexlify(ct_hex)
key = SHA256.new(password.encode()).digest()
iv = b'\x00' * 16

cipher = AES.new(key, AES.MODE_CBC, iv)
pt = unpad(cipher.decrypt(ct), AES.block_size)
print(pt.decode('utf-8', errors='replace'))
