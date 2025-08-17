---
title: "Unlock the Encrypted Flag"
categories: "Reverse Engineering"
tags: 
draft: false
completedDuringEvent: true
submitted: true
flags: flag: QUESTCON{3ncrypt3d_fl4g_r3v34l}
---
## Scenario

> You’ve stumbled upon a secure system that hides its flag behind an encrypted file. A Python program is provided, allowing you to check if a password can decrypt the flag. Your mission is to reverse-engineer the program to find the correct password, use it to decrypt the flag, and present the solution in the correct CTF flag format. Can you find the password and unlock the encrypted flag? (Run this Python program in the same directory as this encrypted flag.)

## Solution

The challenge provides a file named `unlock_the_encrypted_flag.py` which is a Python script. The script is just normal Python code. But inside it there is a variable called `pw_parts` which contains the password split into five parts. The script will then concatenate the five parts and use it to decrypt the flag.

```py
pw_parts = ["ak98", "-=90", "adfjhgj321", "sleuth9000"]
```

Running the script will prompt for a password. The password is `ak98-=90adfjhgj321sleuth9000`. The script will then use the password to decrypt the flag.
