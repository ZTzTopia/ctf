---
title: "Actual Reversing"
category: Reverse Engineering
tags: 
draft: false
completedDuringEvent: true
submitted: true
flag: bronco{r3v3r5ed_3n0ugh?}
---
> Here is something reversible. :)

By shwhale

---

ok!! **Actual Reversing**.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char i; // [rsp+7h] [rbp-59h]
  int v5; // [rsp+8h] [rbp-58h]
  int v6; // [rsp+Ch] [rbp-54h]
  char s[72]; // [rsp+10h] [rbp-50h] BYREF
  unsigned __int64 v8; // [rsp+58h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  puts("Welcome to the transformer! We take what you have, and make it into what you have always wanted!");
  printf("What do you have to offer?\n> ");
  fgets(s, 64, _bss_start);
  s[strcspn(s, "\n")] = 0;
  v5 = 0;
  v6 = 0;
  while ( s[v5] )
  {
    for ( i = s[v5]; i; i >>= 1 )
      v6 += i & 1;
    ++v5;
  }
  if ( v6 == 108 )
  {
    puts("Here's my perscription:");
    perscribe(s);
    printf("%s", TRUTH);
  }
  else
  {
    puts("That'll NEVER turn into what you want!");
  }
  return 0;
}
```

The binary reads a string from the user, and then calculates the number of bits set in the string. If the number of bits set is 108, it calls a function `perscribe` with the string. The `perscribe` function then does some bit manipulation and prints out a message.

```c
unsigned __int64 __fastcall perscribe(char *a1)
{
  void *v1; // rsp
  __int64 v3; // [rsp+0h] [rbp-60h] BYREF
  char *s; // [rsp+8h] [rbp-58h]
  int i; // [rsp+18h] [rbp-48h]
  int j; // [rsp+1Ch] [rbp-44h]
  int k; // [rsp+20h] [rbp-40h]
  int v8; // [rsp+24h] [rbp-3Ch]
  int v9; // [rsp+28h] [rbp-38h]
  int v10; // [rsp+2Ch] [rbp-34h]
  int v11; // [rsp+30h] [rbp-30h]
  int v12; // [rsp+34h] [rbp-2Ch]
  __int64 v13; // [rsp+38h] [rbp-28h]
  __int64 *v14; // [rsp+40h] [rbp-20h]
  unsigned __int64 v15; // [rsp+48h] [rbp-18h]

  s = a1;
  v15 = __readfsqword(0x28u);
  v8 = strlen(TRUTH);
  v9 = 8 * v8;
  v13 = 8 * v8 - 1LL;
  v1 = alloca(16 * ((8 * v8 + 15LL) / 0x10uLL));
  v14 = &v3;
  for ( i = 0; i < 8 * v8; ++i )
    *((_BYTE *)v14 + i) = 0;
  v10 = strlen(s);
  for ( i = 0; i < v10; ++i )
  {
    for ( j = 0; j <= 7; ++j )
    {
      v11 = 1 << j;
      if ( ((1 << j) & s[i]) != 0 )
      {
        v12 = 8 * i + j;
        for ( k = 0; ((TRUTH[k >> 3] >> (k & 7)) & 1) == 0 || *((_BYTE *)v14 + k); ++k )
          ;
        printf("Take %d of these, then\n", (unsigned int)(k - v12));
        *((_BYTE *)v14 + k) = 1;
      }
    }
  }
  puts("You're done!");
  return v15 - __readfsqword(0x28u);
}
```

The `perscribe` function initializes an array of bytes `v14` with zeros. It then iterates over each byte in the input string `s`, and for each bit set in the byte, it finds the first bit set in the `TRUTH` string that has not already been used. It then prints out `"Take X of these, then"`, where `X` is the difference between the bit position in the `TRUTH` string and the bit position in the input string. It then marks that bit as used.

![alt text](image.png)

Matching with `TRUTH`
- The function scans through the bits of `TRUTH` (`for (k = 0; ... ; ++k)`) looking for:
    - The first bit that is set (`((TRUTH[k >> 3] >> (k & 7)) & 1) != 0`).
    - The first bit that has not already been used (`!*((_BYTE *)v14 + k)`).
- Once it finds such a bit, it prints `"Take X of these, then"`, where `X = k - v12` (the offset between input and `TRUTH`).
- It marks that bit position as used (`*((_BYTE *)v14 + k) = 1`).

They give perscription for the correct input string. We can use this perscription to recover the flag.

```
Here's my perscription:
Take -1 of these, then
Take -4 of these, then
Take 0 of these, then
Take -1 of these, then
Take 1 of these, then
Take 1 of these, then
Take 3 of these, then
Take 2 of these, then
Take 2 of these, then
Take 3 of these, then
Take 3 of these, then
Take 8 of these, then
Take 11 of these, then
Take 12 of these, then
Take 12 of these, then
Take 13 of these, then
Take 14 of these, then
Take 15 of these, then
Take 14 of these, then
Take 16 of these, then
Take 15 of these, then
Take 15 of these, then
Take 14 of these, then
Take 17 of these, then
Take 19 of these, then
Take 19 of these, then
Take 19 of these, then
Take 19 of these, then
Take 20 of these, then
Take 20 of these, then
Take 19 of these, then
Take 25 of these, then
Take 27 of these, then
Take 28 of these, then
Take 28 of these, then
Take 26 of these, then
Take 28 of these, then
Take 28 of these, then
Take 28 of these, then
Take 28 of these, then
Take 26 of these, then
Take 27 of these, then
Take 25 of these, then
Take 27 of these, then
Take 26 of these, then
Take 28 of these, then
Take 28 of these, then
Take 27 of these, then
Take 28 of these, then
Take 26 of these, then
Take 32 of these, then
Take 31 of these, then
Take 30 of these, then
Take 31 of these, then
Take 31 of these, then
Take 30 of these, then
Take 31 of these, then
Take 30 of these, then
Take 30 of these, then
Take 29 of these, then
Take 28 of these, then
Take 29 of these, then
Take 31 of these, then
Take 28 of these, then
Take 27 of these, then
Take 28 of these, then
Take 29 of these, then
Take 29 of these, then
Take 31 of these, then
Take 33 of these, then
Take 33 of these, then
Take 32 of these, then
Take 32 of these, then
Take 32 of these, then
Take 32 of these, then
Take 32 of these, then
Take 29 of these, then
Take 32 of these, then
Take 33 of these, then
Take 32 of these, then
Take 32 of these, then
Take 28 of these, then
Take 32 of these, then
Take 30 of these, then
Take 31 of these, then
Take 30 of these, then
Take 30 of these, then
Take 31 of these, then
Take 30 of these, then
Take 33 of these, then
Take 35 of these, then
Take 33 of these, then
Take 39 of these, then
Take 37 of these, then
Take 37 of these, then
Take 37 of these, then
Take 37 of these, then
Take 37 of these, then
Take 38 of these, then
Take 39 of these, then
Take 41 of these, then
Take 41 of these, then
Take 40 of these, then
Take 39 of these, then
Take 39 of these, then
Take 39 of these, then
Take 39 of these, then
Take 39 of these, then
You're done!
Can birds even understand me?
```

The perscription tells us how to construct the flag from the input string. We can write a script to do this.

```py
import math

TRUTH = "Can birds even understand me?"

T = []
for k in range(8 * len(TRUTH)):
    if (ord(TRUTH[k // 8]) >> (k % 8)) & 1:
        T.append(k)

log_d = [
    -1, -4, 0, -1, 1, 1, 3, 2, 2, 3, 3, 8, 11, 12, 12, 13, 14, 15, 14, 16,
    15, 15, 14, 17, 19, 19, 19, 19, 20, 20, 19, 25, 27, 28, 28, 26, 28, 28,
    28, 28, 26, 27, 25, 27, 26, 28, 28, 27, 28, 26, 32, 31, 30, 31, 31, 30,
    31, 30, 30, 29, 28, 29, 31, 28, 27, 28, 29, 29, 31, 33, 33, 32, 32, 32,
    32, 32, 29, 32, 33, 32, 32, 28, 32, 30, 31, 30, 30, 31, 30, 33, 35, 33,
    39, 37, 37, 37, 37, 37, 38, 39, 41, 41, 40, 39, 39, 39, 39, 39
]

b_positions = []
for j, d in enumerate(log_d):
    b_j = T[j] - d
    b_positions.append(b_j)

max_bit = max(b_positions)
num_bytes = math.ceil((max_bit + 1) / 8)

input_bytes = [0] * num_bytes

for pos in b_positions:
    byte_index = pos // 8
    bit_index = pos % 8
    input_bytes[byte_index] |= (1 << bit_index)

print(f'Flag: {"".join(chr(b) for b in input_bytes)}')
```
