# ENIGMA M3

---
category: Cryptography
tags: 
  - enigma
  - enigma-m3
---

## Scenario

> Welcome to the Enigma challenge! Your task is to decrypt the given ciphertext using the Enigma M3 settings provided below. The flag is hidden within the decrypted message.
>
> Enigma Settings: Rotors: I, II, III Ring Settings: D, D, D Initial Rotor Positions: A, B, C Reflector: B Plugboard Connections: A ↔ G, B ↔ H
>
> Ciphertext: ymnjp znmjo gteqj cjwwh qljtd nprmp g
>
> Note: You will have to rearange the letters and bring it in flag format QUESTCON{seperate_space} Also remember to replace space to _

## Solution

The challenge provides an Enigma M3 settings and a ciphertext. The Enigma M3 settings are as follows:
- Rotors: I, II, III
- Ring Settings: D, D, D
- Initial Rotor Positions: A, B, C
- Reflector: B
- Plugboard Connections: A ↔ G, B ↔ H

The ciphertext is `ymnjp znmjo gteqj cjwwh qljtd nprmp g`. We can decrypt the ciphertext using the Enigma M3 settings provided. We can use the [Enigma Simulator](https://cryptii.com/pipes/enigma-machine) to decrypt the ciphertext.

Or 

Check the [`solution.py`](solution.py) file for the solution.

## Flag

`QUESTCON{BERLIN_HAD_SECRETS_BENEATH_HIS_CHARM}`
