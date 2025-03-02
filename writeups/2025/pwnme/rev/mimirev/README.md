---
title: Mimirev
category: Reverse Engineering
tags: 
draft: true
completedDuringEvent: true
submitted: true
flag: PWNME{R3v3rS1ng_Compil0_C4n_B3_good}
---
> A new and obscure programming language, MimiLang, has surfaced. It runs on a peculiar interpreter, but something about it feels… off. Dive into its inner workings and figure out what's really going on. Maybe you'll uncover something unexpected.
>
> Author : `Lxt3h`
>
> Flag format: `PWNME{.........................}`

by Lxt3h

---

```
init vv = 0;
init vvv = 1;
init expr = 0;

while vvv < 314159 {
    if expr == 273262 {
        verifyProof(vvv, vv);
        rea vvv = 1;
        break;
    } else {
        rea vvv = vvv + 1;
        rea vv = 314159 - vvv;
        rea expr = (vvv * vvv + vv * vv * vv - vvv * vv) % 1048573;
    }
}
```

Compile and running the code with following command:

```
./mimicompiler -f solver.mimi
```
