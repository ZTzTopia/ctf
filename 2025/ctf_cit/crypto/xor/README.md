---
title: XOR
categories: Cryptography
tags: 
draft: false
completedDuringEvent: true
submitted: true
flags: CIT{Yft5Kx09E4Wx}
---
> PFFUQYTUONPSK5LAMNDXGJ35ER4CM5C7ORETY3A=
>
> Flag Format: CIT{example_flag}

by `ronnie`

---

Ah another guessy crypto challenge. The challenge gives us a `Base32` string because all the string is uppercase.

The step to solve this challenge:

- Decode the `Base32` string
- Use [dCode Cipher Identifier](https://www.dcode.fr/cipher-identifier) to identify the cipher used. The result is a `ROT47` cipher.
- Decode the string using `ROT47` cipher. The result is a `Base64` string.
- Decode the `Base64` string. The result is a gibberish string.
- Find the pattern in the gibberish string use `XOR` with the flag format `CIT{`. It will reveal the key used to `XOR` the string, which is `duck`.
- Use the key to `XOR` the gibberish string.

Link to [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base32('A-Z2-7%3D',true)ROT47(47)From_Base64('A-Za-z0-9%2B/%3D',true,false)XOR(%7B'option':'UTF8','string':'duck'%7D,'Standard',false)&input=UEZGVVFZVFVPTlBTSzVMQU1ORFhHSjM1RVI0Q001QzdPUkVUWTNBPQ&oeol=CR).
