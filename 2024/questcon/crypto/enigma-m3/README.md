---
title: "ENIGMA M3"
categories: Cryptography
tags: 
  - enigma
  - enigma-m3
draft: false
completedDuringEvent: true
submitted: true
flag: QUESTCON{BERLIN_HAD_SECRETS_BENEATH_HIS_CHARM}
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

The ciphertext is `ymnjp znmjo gteqj cjwwh qljtd nprmp g`. We can decrypt the ciphertext using the Enigma M3 settings provided. We can use the [Enigma](https://gchq.github.io/CyberChef/#recipe=Enigma('3-rotor','LEYJVCNIXWPBQMDRTAKZGFUHOS','A','A','EKMFLGDQVZNTOWYHXUSPAIBRCJ%3CR','D','A','AJDKSIRUXBLHWTMCQGZNPYFVOE%3CF','D','B','BDFHJLCPRTXVZNYEIWGAKMUSQO%3CW','D','C','AY%20BR%20CU%20DH%20EQ%20FS%20GL%20IP%20JX%20KN%20MO%20TZ%20VW','AG%20BH',true)&input=eW1uanAgem5tam8gZ3RlcWogY2p3d2ggcWxqdGQgbnBybXAgZw) to decrypt the ciphertext.

Or check the [solver.py](solver.py) file for the solution.
