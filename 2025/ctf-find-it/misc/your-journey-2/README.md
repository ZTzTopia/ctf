---
title: your-journey-2
categories: Miscellaneous
tags: 
draft: false
completedDuringEvent: true
submitted: true
flags: flag: FindITCTF{k0n0h4_m4ju_m4sy4r4k4t_m4kmur}
---
> perjalananmu berlanjut, tahun lalu masih adem sekarang tidak. kalau berhenti sekarang ntar malah ga sampe sampe, mending gas aja terus

by `hilmo`

---

We are given two Python files, `main.py` and `word.py`. The `word.py` file contains a blacklist of words that must not appear in the input. The `main.py` file contains the code that will execute our input. If we enter the correct input, we will get the flag.

```py
import re

from hidden import *
from word import *

while True:
    ans = (
        input(
            f'{lagu}\nHmm something seems wrong with the song, isn't it supposed to be "Ayo Ayo Ganyang si b.e.b.a.n 🌸"\n$'
        )
        .strip()
        .lower()
    )

    if any(char in ans for char in block):
        print(
            f'\nUnfortunately, you used forbidden words. Now the "official" has been promoted\n'
        )
        break
    if not re.match("^[\x20-\x7E]*$", ans):
        print("\nOh no, you're trying to use non-alphabet characters :>\n")
        break
    try:
        eval(ans + "()")
        print("Is this the right end?\n")
    except Exception as e:
        print(e)
        print(f'\n{ascii2}\nOh no, you were attacked by "The colleagues of the official"\n')
        break
```

Since the blacklist is not too extensive, we can try each word one by one. First, I am curious about the content of `hidden.py`, so I immediately use the `help` function to check the contents of `hidden.py`. It turns out that the module contains a function to read folders.

```
help> hidden
Help on module hidden:

NAME
    hidden

FUNCTIONS
    viewfolder(path: str)

DATA
    FLAG = 'FIndITCTF{y0u_f0und_1t!_or_d1d_y0u?}'

FILE
    /challenge/hidden.py
```

We can attempt to read the folder in the current directory by calling the `viewfolder` function.

```
$viewfolder('.')
endingsatu
flag.txt
main.py
hidden.py
word.py
endingtiga
endingdua
```

We see that there are many folders inside, as well as several fake flags. So, I decided to try each one and eventually found the real flag in the `endingdua` folder by executing the following code:

```py
print(open('endingdua/flag.txt').read())
```
