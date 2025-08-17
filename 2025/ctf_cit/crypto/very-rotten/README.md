---
title: "Very Rotten"
categories: Cryptography
tags: 
draft: false
completedDuringEvent: true
submitted: true
flags: CIT{Y0u_are_s00_ROTT3N_MgOxrNY138DpqxO96rcx}
---
> TFJDe0gzeV9ldmlfdzMzX0FYQ0M2V19Wa1hidldINDYxTXR1YlgyOXZnYn0=
>
> Flag Format: CIT{example_flag}

by `ronnie`

---

Ah what a guessy crypto challenge. The challenge gives us a `Base64` string.

The step to solve this challenge:

- Decode the `Base64` string
- Brute force the `ROT13` cipher (Rotate uppercase and numbers) and you will find the flag format `CIT{}` in amount `17`.
- Brute force the `ROT13` cipher (Rotate lowercase) and you will find the english readable words in amount `22`.

Link to [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)ROT13_Brute_Force(false,true,true,100,0,true,'')Fork('%5C%5Cn','%5C%5Cn',false)ROT13_Brute_Force(true,false,false,100,0,true,'')&input=VEZKRGUwZ3plVjlsZG1sZmR6TXpYMEZZUTBNMlYxOVdhMWhpZGxkSU5EWXhUWFIxWWxneU9YWm5ZbjA9).
