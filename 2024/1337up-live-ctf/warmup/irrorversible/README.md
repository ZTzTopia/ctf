---
title: IrrORversible
categories: Miscellaneous
tags: 
completedDuringEvent: true
submitted: true
flags: flag: INTIGRITI{b451c_x0r_wh47?}
draft: false
---
## Scenario

> So reversible it's practically irreversible
>
> `nc irrorversible.ctf.intigriti.io 1330`

By CryptoCat

## Solution

The challenge is a simple XOR encryption. The server encrypts the input text with a sentence that contains the flag and sends the ciphertext back to the client. The client can then extract the sentence by XORing the ciphertext with the previously sent plaintext.

```py
from pwn import *

def xor(ciphertext_hex, known_plaintext):
    ciphertext = bytes.fromhex(ciphertext_hex)
    plaintext = known_plaintext.decode()

    key = ''
    for i in range(len(plaintext)):
        key += chr(ciphertext[i] ^ ord(plaintext[i]))
    
    return key

context.log_level = 'debug'

r = remote('irrorversible.ctf.intigriti.io', 1330)

r.recvuntil(b'Please enter the text you would like to encrypt:')

plaintext = cyclic(233)
r.sendline(plaintext)

r.recvuntil(b'Your encrypted ciphertext (hex format):')
r.recvline()

ciphertext_hex = r.recvline(231).strip().decode()
ciphertext_hex = ciphertext_hex.replace('\x1b[0m', '')
ciphertext_hex = ciphertext_hex.replace('\x1b[32m', '')

sentence = xor(ciphertext_hex, plaintext)
log.info(f'Sentence: {sentence}')
```