---
category: Crypto 
tags: 
  - vigenere
---

# Old Connections?

## Scenario

> Check out following pdf for more information!
>
> Flag format: QUESTCON{something}

## Solution

The PDF contains a Vigenère cipher table. The table is used to encrypt and decrypt messages using a keyword. The keyword is repeated to match the length of the message. The keyword is used to shift the alphabet to encrypt the message.

The ciphertext is `UFJKXQZQUNB`. The keyword is `SOLVECRYPTO`. We can decrypt the message using the Vigenère cipher table provided in the PDF. We can use the the [Vigenère Decode](https://gchq.github.io/CyberChef/#recipe=Vigen%C3%A8re_Decode('SOLVECRYPTO')&input=VUZKS1hRWlFVTkI) to decrypt the message.

Or check the [`solution.py`](solution.py) file for the solution.

## Flag

`QUESTCON{CRYPTOISFUN}`
