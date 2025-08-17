---
title: Weak
categories: Cryptography
tags: 
draft: true
completedDuringEvent: true
submitted: true
flags: FindITCTF{W1_w0k_d3_t0k_n0t_0nl1_t0k_d3_t0k}
---
> Simple login. By the way, I think using a common secret is a bad idea 🗿

by `hilmo`

---

Given a connection and the source code of the file `source.py`. Let's look at the source code.

```py
def register(name):
    token = pce(name)

    data = {
        "name": name,
        "user_id": random.randint(1, 100),
        "token": token,
    }

    cookie = jwt.encode(data, secret, algorithm="HS256")
    print("Store this cookie for login:", cookie)
```

This function allows a user to register. It creates a user token by calling the `pce()` function, and generates a JWT (JSON Web Token) using a shared secret. The token is then returned to the user as a "cookie" used for future authentication.

```py
def pce(str):
    iv = get_random_bytes(16)

    spce = (
        f"name={str}_{prefix * random.randint(1, 100)};uid={random.randint(1,10000000)}"
    )
    bpce = bytes(spce, "utf-8")
    p = pad(bpce, 16)
    c = AES.new(secret2, AES.MODE_CBC, iv)
    e = c.encrypt(p)

    return f"{e.hex()}+{iv.hex()}+{rand.hex()}"


def pce_decrypt(enc):
    e = bytes.fromhex(enc[0])
    iv = bytes.fromhex(enc[1])

    c = AES.new(secret2, AES.MODE_CBC, iv)
    d = c.decrypt(e)

    return unpad(d, AES.block_size).decode("utf-8")
```

The `pce()` function is responsible for creating the token's encrypted part using AES in CBC mode. The structure of the plaintext being encrypted includes the username and a UID. It returns the ciphertext, IV, and a static random value as a token string.
The `pce_decrypt()` function does the reverse—it decrypts this token back into plaintext using the same key and IV.

```py
def login(name, cookie):
    decoded = jwt.decode(cookie, secret, algorithms=["HS256"])

    if decoded["name"] != name:
        print("Whoops! This cookie is not for you.")
        return

    if decoded["name"] == "admin":
        print(pce_decrypt(decoded["token"].split("+")))
        if (
            decoded["name"]
            == pce_decrypt(decoded["token"].split("+")).split(";")[0].split("=")[1]
            and rand.hex() == decoded["token"].split("+")[2]
        ):
            print("GG, here your flag: ", FLAG)
            return
        else:
            print("Whoops! This cookie is not for you.")

    print("Welcome back, " + decoded["name"] + "!")
```

In the login function, the server first decodes the JWT and checks that the username in the cookie matches the submitted name.
If the username is `admin`, it decrypts the token and performs two checks:

* The decrypted name inside the token must also be `"admin"`.
* The static random value at the end of the token must match the global `rand.hex()` value.

If both pass, the flag is printed. Otherwise, the access is denied.

---

To exploit this vulnerability, we start by registering a new user, such as `adm1n`, and capture the JWT token generated. We then extract the AES IV and ciphertext from the token.

Due to the use of AES in CBC mode, we can apply a **bit-flipping attack** to the IV in order to manipulate the first block of decrypted plaintext. Our goal is to modify the decrypted string so that the `"name=adm1n_"` part becomes `"name=admin;"`.
We don't need to decrypt the ciphertext—just control what it decrypts to by flipping bits in the IV.

After adjusting the IV, we recombine the ciphertext, modified IV, and original random value, and construct a new JWT. We also change the `name` field in the JWT payload to `"admin"`.
This tricks the server into thinking the token belongs to `admin` and passes both verification checks.

Since the JWT is signed using a common secret key (`secret`) and the algorithm is `HS256`, it's susceptible to **brute-force attacks** if the secret is weak or guessable. Tools like `jwt_tool.py` or `John the Ripper` can try to brute-force the JWT signature using wordlists such as `rockyou.txt`.

```py
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
```
