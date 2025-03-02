from pwn import *
import ctypes
import binascii
import hashlib
import base64
import json

libc = ctypes.CDLL('libc.so.6')
libc.srand(libc.time(0))

class RC4:
    def __init__(self, key: bytes):
        # Initialize the array with values 0-255
        self.state = [i for i in range(256)]
        # Reset position tracking
        self.x = 0
        self.y = 0
        
        # Key scheduling algorithm
        j = 0
        for i in range(256):
            # In C++ code, a2[v3 & 3] is accessing key with modulo 4
            # Assuming key is a bytes object or bytearray
            j = (j + self.state[i] + key[i % len(key)]) & 0xFF
            # Swap values
            self.state[i], self.state[j] = self.state[j], self.state[i]
            
    def get_bit(self):
        # Increment x and wrap around to stay within 0-255
        self.x = (self.x + 1) % 256
        
        # Get value at state[x]
        x_val = self.state[self.x]
        
        # Update y using value at state[x]
        self.y = (self.y + x_val) % 256
        
        # Swap values at state[x] and state[y]
        self.state[self.x], self.state[self.y] = self.state[self.y], self.state[self.x]
        
        # Return value at state[(state[x] + state[y]) % 256]
        return self.state[(self.state[self.x] + self.state[self.y]) % 256]
        
    def decrypt(self, encrypted_data: bytes):
        result = bytearray()
        
        for byte in encrypted_data:
            # XOR each byte with the next byte from the RC4 keystream
            decrypted_byte = byte ^ self.get_bit()
            result.append(decrypted_byte)
            
        return bytes(result)
    
    def encrypt(self, data: bytes):
        return self.decrypt(data)

def decrypt(key, data):
    crc32_value = binascii.crc32(key)
    libc.srand(crc32_value)

    v6 = libc.rand()
    random_key = libc.rand() % 0xFFFF * (v6 % 0xFFFF)
    random_key = random_key.to_bytes(4, 'big')

    rc4 = RC4(random_key)
    return rc4.decrypt(binascii.unhexlify(data))

def encrypt(key, data):
    crc32_value = binascii.crc32(bytearray(key))
    libc.srand(crc32_value)

    v6 = libc.rand()
    random_key = libc.rand() % 0xFFFF * (v6 % 0xFFFF)
    random_key = random_key.to_bytes(4, 'big')

    rc4 = RC4(random_key)

    encrypted_data = rc4.encrypt(data)
    return encrypted_data.hex()

def checker(key, data):
    sha1_hash = hashlib.sha1(decrypt(key, data)).hexdigest()

    expected_hash = "b039d6daea04c40874f80459bff40142bd25b995"
    return sha1_hash == expected_hash

data = decrypt(b'Noa',b'e3bfbdf16314ebed7bd2c608ae530692724cc3a5')
print(f'Decrypted data: {data}')
print(f'Encrypted data: {encrypt(b"Noa", data)}')
print(f'Checker: {checker(b"Noa", b"e3bfbdf16314ebed7bd2c608ae530692724cc3a5")}')

context.log_level = 'debug'

r = remote('c4license-3a7a8c81137937c1.deploy.phreaks.fr', 443, ssl=True)

current = 0
while True:
    r.recvuntil(b'Your license for ')
    user = r.recv()
    user = user.split(b' ')[0]

    json_data = {
        'user': user.decode(),
        'serial': encrypt(user, data)
    }
    base64_json = base64.b64encode(json.dumps(json_data).encode()).decode()
    r.sendline(base64_json)

    current += 1
    if current == 100:
        break

r.interactive()
