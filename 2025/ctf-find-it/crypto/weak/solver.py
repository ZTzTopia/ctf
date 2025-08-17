import json

import jwt
from pwn import *


def bit_flipping(ciphertext, position, xor_value):
    """
    Modifies the encrypted text by XORing a specified value at a specified position.

    :param ciphertext: (bytes) The input ciphertext.
    :param position: (int) The position in the ciphertext where XOR should be applied.
    :param xor_value: (int) The value to XOR at the specified position.
    :return: (bytes) The modified ciphertext.
    :raises ValueError: If the position or xor_value is not of type 'int' or if the position is invalid.
    :raises Exception: If an error occurs during bit flipping.
    """
    try:
        ciphertext = bytes.fromhex(ciphertext)
        byte_list = bytearray(ciphertext)
        if not isinstance(position, int) or not isinstance(xor_value, int):
            raise ValueError('Position and xor_value must be integers')

        # print(byte_list[16:])
        # if position < 0 or position >= len(byte_list[16:]):
        #     raise ValueError("Invalid position")
        byte_list[position] ^= xor_value
        return bytes(byte_list)
    except Exception as e:
        print(f'Bit flipping error: {e}')
        raise


# for i in range(128):
#     c = AES.new(b"1234567890123456", AES.MODE_CBC, bit_flipping(
#         '01d1b8ca22ef2b83e9def93a8d83c3a9',
#         8,
#         i))
#     d = c.decrypt(bytes.fromhex('b8916ad7004d32356f34639d85861830ab1d16dbd4a74e6f25c372dc6021f4ef'))
#     # if d[10] == 'g':
#     print(f'{i}: {d}')

# context.log_level = 'debug'

r = remote('ctf.find-it.id', 7301)

r.sendlineafter(b'Enter your choice (1/2/3):', b'1')
r.sendlineafter(b'Enter your name:', b'adm1n')

r.recvuntil(b'Store this cookie for login:')
cookie = r.recvline().strip()
log.info(f'Cookie: {cookie}')

payload = base64.b64decode(cookie.split(b'.')[1] + b'==').decode()
payload = json.loads(payload)

user_id = payload['user_id']
token = payload['token']
iv = token.split('+')[1]

bit_flip = bit_flipping(iv, 8, 88).hex()

bit_flip = bit_flipping(bit_flip, 10, 100).hex()

token = (
    payload['token'].split('+')[0]
    + '+'
    + bit_flip
    + '+'
    + payload['token'].split('+')[2]
)

payload = {'user_id': user_id, 'name': 'admin', 'token': token}

cookie = jwt.encode(payload, b'internet', algorithm='HS256')

r.sendlineafter(b'Enter your choice (1/2/3):', b'2')
r.sendlineafter(b'Enter your name:', b'admin')
r.sendlineafter(b'Enter your cookie:', cookie.encode())

r.interactive()
