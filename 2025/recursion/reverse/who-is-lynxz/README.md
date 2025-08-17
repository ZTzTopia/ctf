---
title: "Who is Lynxz?"
categories: Reverse Engineering
tags: 
draft: false
completedDuringEvent: true
submitted: true
flags: RECURSION{lynxz_w4s_a_gr0wt0p14_hack3r_back_th3n}
---
> I have an online friend from 7 years ago but I didn't know who he was before I met him 7 years ago. I only know that he was a great hacker back then. Can you help me find out who he was?
>
> Something pointing and change every 5 seconds. It's a bit hard to see. Maybe you can help me?
>
> Note: Maybe you need **Cheat Engine** to solve this challenge.

by `ztz`

---

## Find the `ARCHIVE` file inside the `.rsrc\0\RCDATA\` directory

First, navigate to the directory path `\.rsrc\0\RCDATA\` inside the given file. This location contains a file labeled `ARCHIVE`. The `ARCHIVE` file is actually a `.CETRAINER` file.

## Use the `CETRAINER` to Extract the `.CT` File

Once you've located the .CETRAINER file, you need to extract the .CT file from it. To do this, you will need to use a CETRAINER extractor or decryptor. These tools are available online, and you can easily find one with a quick search.

## Decode the Encoded Lua Code

Inside the `.CT` file, you will likely find Lua code that has been encoded using a function called `encodeFunction`. This is done to obfuscate the actual content, including the flag. Search online for a decoder for the `encodeFunction` encoding. There are many decoders available that will help reverse the encoding.

## Find the Flag in the Decoded Lua Code

The decoded Lua script contains the flag, but it is **XOR-encrypted** with a **random string**. However, the random string is **generated using a fixed seed**, which means the same string is created every time the script runs.

Once you have the random string, you can use it to XOR-decrypt the encrypted flag. Here's an script of how you can do this in `Python`:

```py
cipher_text = "60 08 71 1b 28 15 79 17 7c 36 5e 37 14 3e 4a 07 45 79 41 11 1b 19 57 2a 02 3a 46 7e 0a 77 04 07 5a 2c 51 25 49 34 6f 3a 53 2e 59 11 0e 2e 03 36 4f"
key = "2M2NzF0X"

def xor_decrypt(cipher_text, key):
    cipher_bytes = bytes.fromhex(cipher_text)
    key_bytes = key.encode('utf-8')
    decrypted_bytes = bytearray()
    
    for i in range(len(cipher_bytes)):
        decrypted_bytes.append(cipher_bytes[i] ^ key_bytes[i % len(key_bytes)])
    
    return decrypted_bytes.decode('utf-8')

print(f'Flag: {xor_decrypt(cipher_text, key)}')
```
