---
title: "Reversing for Ophidiophiles"
categories: Reverse Engineering
tags: 
draft: false
completedDuringEvent: true
submitted: true
flags: flag: bronco{charge_away}
---
> Do you love python? Or at least tolerate it? Then this is the challenge for you!
>
> When run with the correct flag, the given file prints: `23a326c27bee9b40885df97007aa4dbe410e93`.
>
> What is the flag?

By shwhale

---

The challenge provides a python script that encrypts the flag and prints the ciphertext. The script is as follows:

```py
flag = input()
carry = 0
key = "Awesome!"
output = []
for i,c in enumerate(flag):
    val = ord(c)
    val += carry
    val %= 256
    val ^= ord(key[i % len(key)])
    output.append(val)
    carry += ord(c)
    carry %= 256

print(bytes(output).hex())
```

So here the flag is added to the carry where at the beginning the carry is 0 after that there will be a check if the flag is outside the ascii then the modulus is 256 after adding the carry then it will be continued with the XOR operation with the Awesome key! after that it will be added to the output array variable after that the variable will be added with the ascii of the current character if the carry is outside the ascii range then it will be modulated by 256.

To decrypt the flag, we can reverse the encryption process. We can start by converting the ciphertext to bytes, and then decrypting each character in reverse order. The decryption process is as follows:

```py
ciphertext = "23a326c27bee9b40885df97007aa4dbe410e93"
ciphertext = bytes.fromhex(ciphertext)
key = "Awesome!"
carry = 0

flag = []
for i, c in enumerate(ciphertext):
    c ^= ord(key[i % len(key)])
    c -= carry
    c %= 256
    flag.append(c)
    carry += c
    carry %= 256

print(f'Flag: {bytes(flag).decode()}')
```
