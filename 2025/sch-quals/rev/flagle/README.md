---
title: flagle
categories: "Reverse Engineering"
authors: requiiem
tags: 
draft: false
completedDuringEvent: true
submitted: true
points: 456
solves: 9
flags: SCH25{since_when_did_wordle_became_this_annoying__6675636b}
---

> just play it bro

---

This challenge is a binary that performs flag verification in a unique way, similar to the game Wordle. After analysis, the main function that executes the verification logic is as follows:

```c
__int64 sub_40390B()
{
  _QWORD v1[109]; // [rsp+10h] [rbp-380h] BYREF
  void (__fastcall *v2)(_QWORD *); // [rsp+378h] [rbp-18h]
  unsigned __int64 v3; // [rsp+380h] [rbp-10h]
  signed int i; // [rsp+38Ch] [rbp-4h]

  memset(v1, 0, sizeof(v1));
  v1[105] = &unk_A50120;
  v1[106] = &unk_A501D0;
  v1[107] = &unk_A50200;
  v3 = 0xDEADBEEFCAFEBABELL;
  for ( i = 0; (unsigned int)i <= 7; ++i )
    *(&off_A50260 + i) = (_UNKNOWN *)(v3 ^ (unsigned __int64)*(&off_A50260 + i));
  while ( LODWORD(v1[0]) != 7 )
  {
    v2 = (void (__fastcall *)(_QWORD *))(v3 ^ (unsigned __int64)*(&off_A50260 + LODWORD(v1[0])));
    v2(v1);
  }
  return 0;
}
```

Here, it calls the functions in the `off_A50260` array based on the value of `v1[0]`. Then, it will determine what to do with `v1[0]` to call the next function. After reversing, it turns out that these functions check our guesses character by character and provide feedback similar to WordLee.

```c
_DWORD *__fastcall sub_40363B(_DWORD *a1)
{
  _DWORD *result; // rax
  int v2; // [rsp+18h] [rbp-8h] BYREF
  int i; // [rsp+1Ch] [rbp-4h]

  v2 = 0;
  for ( i = 0; i <= 58; ++i )
    sub_4035D0(&a1[3 * i + 33], &v2);
  sub_7DF890(10);
  if ( v2 == 59 )
  {
    result = a1;
    *a1 = 6;
  }
  else
  {
    a1[2] = v2;
    result = a1;
    *a1 = 4;
  }
  return result;
}

__int64 __fastcall sub_4035D0(__int64 a1, __int64 a2, int a3, int a4, int a5, int a6)
{
  __int64 result; // rax
  _DWORD *v7; // [rsp+0h] [rbp-10h]

  if ( *(_DWORD *)(a1 + 8) )
    return sub_7CFAE0((unsigned int)&unk_8910BA, (unsigned int)&unk_8910BD, a3, a4, a5, a6, a2, a1); // check green
  sub_7CFAE0((unsigned int)&unk_8910BA, (unsigned int)&unk_8910B5, a3, a4, a5, a6, a2); // check yellow
  result = (__int64)v7;
  ++*v7;
  return result;
}
```

But since our character will give green feedback if it's correct, we can use this to brute-force each character (malas reverse aja ini mah awokaow). So, we try all possible characters in a certain position, then see how many green feedback we get. If we get more green feedback than before, the character is correct. Keep in mind that we need to know the flag length first to avoid being hit by a flag length check.

```sh
$ ./flagle
Attempt 1/3
Enter your guess (A-Z, a-z, 0-9, _{}): 
SCH25{AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}
🟩🟩🟩🟩🟩🟩⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜🟩
skill issue </3
```

Here is a Python script that automates the brute-force process with parallelization:

```py
from pwn import process
from concurrent.futures import ThreadPoolExecutor, as_completed
import os

TOTAL_LEN = 59
PREFIX = "SCH25{since_when_did_wordle_became_this_annoying_"
CHARSET = "_{}0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
MAX_WORKERS = min(32, (os.cpu_count() or 4) * 2)

flag = PREFIX

def try_candidate(c, attempt):
    p = process("./flagle")
    try:
        p.sendline(attempt)
        resp = p.recvall(timeout=2).decode(errors="ignore")
        green_count = resp.count("🟩")
    except Exception:
        green_count = -1
        resp = ""
    finally:
        try:
            p.close()
        except Exception:
            pass
    return c, green_count, resp

while True:
    threshold = len(flag) - 1
    attempts = [(c, flag + c + "A" * (TOTAL_LEN - len(flag) - 1)) for c in CHARSET]

    found_char = None
    found_resp = None

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(try_candidate, c, att): c for c, att in attempts}
        for fut in as_completed(futures):
            c, green_count, resp = fut.result()
            print(f"Tried {c!r}: {green_count} greens")
            if green_count > threshold:
                found_char = c
                found_resp = resp
                break

    if found_char:
        flag += found_char
        print(f"Found next char: {found_char}, flag so far: {flag}")
        # continue to next position
    else:
        print("No valid character found, stopping.")
        break
```
