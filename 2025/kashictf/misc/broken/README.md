---
title: "Broken?"
categories: Miscellaneous
tags: 
draft: true
completedDuringEvent: false
submitted: false
flags: KashiCTF{Close_Yet_Far_oU2XmjfCX}
---
> You find his laptop lying there and his futile attempt to read a random file..!

---

This challenge involved **HMAC length extension attacks**, exploiting the fact that some cryptographic hash functions (like **SHA-1**) are vulnerable when improperly used for message authentication.

## Understanding the Attack

1. The original signed message:
    ```
    count=10&lat=37.351&user_id=1&long=-119.827&file=random.txt
    ```
    is protected using an HMAC-SHA1 signature:
    ```
    01be4a249bed4886b93d380daba91eb4a0b1ee29
    ```
2. The goal was to modify `file=random.txt` to `file=flag.txt` without knowing the secret key while still generating a valid HMAC.
3. This was possible using **HMAC length extension** because SHA-1 processes data in fixed-size blocks, allowing us to append additional data and calculate a new valid HMAC.

## Exploit Script

The provided script:

1. Iterates over possible **key lengths** (4 to 32 bytes).
2. Uses the [hlextend](https://github.com/stephenbradshaw/hlextend) Python library to generate a **valid extended message** and **new HMAC**.
3. Sends the forged request to the server and checks if the HMAC is accepted.

```py
from pwn import *
import hlextend

# context.log_level = 'debug'

s = hlextend.new('sha1')

for i in range(4, 32):
    r = remote('kashictf.iitbhucybersec.in', 26438)

    new_message = s.extend(b'&file=flag.txt', b'count=10&lat=37.351&user_id=1&long=-119.827&file=random.txt', i, '01be4a249bed4886b93d380daba91eb4a0b1ee29')
    new_message = new_message.decode("latin-1")
    new_message = new_message.encode("unicode_escape")

    new_hash = s.hexdigest()

    r.recvuntil(b'Example: count=10&lat=37.351&user_id=1&long=-119.827&file=random.txt|01be4a249bed4886b93d380daba91eb4a0b1ee29\n')
    r.send(flat([
        new_message,
         b'|',
          new_hash.encode()
    ]))

    if b'Invalid HMAC' not in r.recvline():
        print(f'Found key length: {i}')
        r.interactive()
        break

    r.close()
```
