---
title: Packs
categories: "Reverse Engineering"
authors: aimardcr
tags: 
draft: false
completedDuringEvent: true
submitted: true
points: 0
solves: 0
flags: GEMASTIK18{S1mpl3_P4ck3r_f0r_4_S1mpl3_Ch4ll3nge}
---

> This can be VERY easy or VERY hard for you, depends on how you do it, I guess...

---

After receiving a challenge file named `Packs.exe`, out of curiosity, I tried opening it with a ZIP utility, which revealed an interesting section named `.themida`. This immediately revealed that the executable contained Themida, a well-known commercial software protection program.

![alt text](image.png)

After some research, I discovered a specialized tool for unpacking Themida-protected executables: [Dynamic unpacker and import fixer for Themida/WinLicense 2.x and 3.x](https://github.com/ergrelet/unlicense). Using this tool allowed me to retrieve the original, unpacked executable for analysis.

With the unpacked binary in hand, I proceeded to reverse engineer the main functionality. The primary function responsible for flag validation is shown below:

```c
int sub_401400()
{
  int v0; // edi
  int v1; // edx
  int v2; // eax
  unsigned int v3; // esi
  int v4; // eax
  int v5; // eax
  int v6; // eax
  int v7; // ecx
  unsigned int v8; // ecx
  int v9; // edx
  __int128 v11; // [esp+Ch] [ebp-34h] BYREF
  int v12; // [esp+1Ch] [ebp-24h]
  unsigned int v13; // [esp+20h] [ebp-20h]
  __int64 v14; // [esp+24h] [ebp-1Ch] BYREF
  int v15; // [esp+2Ch] [ebp-14h]
  int v16; // [esp+3Ch] [ebp-4h]

  v12 = 0;
  v11 = 0;
  v13 = 15;
  LOBYTE(v11) = 0;
  v16 = 0;
  sub_401750(std::cout, aFlag);
  sub_401970(std::cin, &v11);
  v15 = 0;
  v14 = 0;
  sub_4012F0(&v14, &v11);
  LOBYTE(v16) = 1;
  v0 = v14;
  v1 = dword_4054BC;
  if ( HIDWORD(v14) - (_DWORD)v14 != dword_4054C0 - dword_4054BC )
  {
    v2 = sub_401750(std::cout, aWrongLength);
    std::istream::operator>>(v2, sub_401B70);
    v1 = dword_4054BC;
  }
  v3 = 0;
  if ( dword_4054C0 != v1 )
  {
    do
    {
      if ( *(_BYTE *)(v0 + v3) != *(_BYTE *)(v1 + v3) )
      {
        v4 = sub_401750(std::cout, aNope);
        std::istream::operator>>(v4, sub_401B70);
        v1 = dword_4054BC;
      }
      ++v3;
    }
    while ( v3 < dword_4054C0 - v1 );
  }
  v5 = sub_401750(std::cout, aYay);
  std::istream::operator>>(v5, sub_401B70);
  if ( v0 )
  {
    v6 = v0;
    v7 = v15 - v0;
    if ( (unsigned int)(v15 - v0) >= 0x1000 )
    {
      v0 = *(_DWORD *)(v0 - 4);
      v8 = v7 + 35;
      if ( (unsigned int)(v6 - v0 - 4) > 0x1F )
LABEL_14:
        invalid_parameter_noinfo_noreturn(v8);
    }
    sub_4021EE(v0);
  }
  if ( v13 > 0xF )
  {
    v9 = v11;
    if ( v13 + 1 >= 0x1000 )
    {
      v9 = *(_DWORD *)(v11 - 4);
      v8 = v13 + 36;
      if ( (unsigned int)(v11 - v9 - 4) > 0x1F )
        goto LABEL_14;
    }
    sub_4021EE(v9);
  }
  return 0;
}
```

This function handles user input and performs the flag validation. It begins by reading input from the user, then processes it through the `sub_4012F0` function, and finally compares the transformed input against a hardcoded value. Looking at the code, we can see the program prints "Wrong Length" if the length doesn't match, "Nope" if any character comparison fails, and "Yay" if the input is correct.

The next critical function to analyze is `sub_4012F0`, which transforms the user input:

```c
unsigned int *__fastcall sub_4012F0(unsigned int *a1, _DWORD *a2)
{
  unsigned int v4; // esi
  unsigned int v5; // eax
  unsigned int i; // edx
  _DWORD *v7; // eax
  int v8; // edx
  int v9; // eax
  unsigned int v10; // eax
  char v11; // cl
  unsigned int v13; // [esp+8h] [ebp-4h]
  _BYTE *v14; // [esp+8h] [ebp-4h]

  *(_QWORD *)a1 = 0;
  a1[2] = 0;
  v13 = a2[4];
  *a1 = 0;
  a1[1] = 0;
  a1[2] = 0;
  if ( v13 )
  {
    sub_401E10(a1, v13);
    v4 = *a1;
    j_memset(*a1, 0, v13);
    a1[1] = v4 + v13;
  }
  v5 = a2[4];
  for ( i = 0; i < v5; v5 = a2[4] )
  {
    v7 = a2;
    if ( a2[5] > 0xFu )
      v7 = (_DWORD *)*a2;
    *(_BYTE *)(i + *a1) = *((_BYTE *)v7 + i);
    ++i;
  }
  v8 = 0;
  if ( v5 )
  {
    do
    {
      v14 = (_BYTE *)(v8 + *a1);
      if ( v8 <= 10 )
        v9 = ((2 * (unsigned __int8)(*v14 - v8)) | ((unsigned __int8)(*v14 - v8) >> 7)) - 5;
      else
        v9 = ((16 * (unsigned __int8)(*v14 - v8 + 1)) | ((unsigned __int8)(*v14 - v8 + 1) >> 4)) ^ 0x7A;
      if ( (v8 & 1) == 0 )
      {
        v10 = (unsigned __int8)((4 * ~(_BYTE)v9) | ((unsigned __int8)~(_BYTE)v9 >> 6));
        v9 = (16 * v10) | (v10 >> 4);
      }
      if ( v8 == 4 )
        v11 = 74 - v9;
      else
        v11 = v8 + v9 + 45;
      ++v8;
      *v14 = v11;
    }
    while ( (unsigned int)v8 < a2[4] );
  }
  return a1;
}
```

This function is responsible for transforming the user's input string before it's compared with the expected value. It performs a series of complex operations on each byte of the input, which vary based on the position of the byte:

1. For bytes at positions ≤ 10, it calculates `((2 * (byte - position)) | ((byte - position) >> 7)) - 5`
2. For bytes at positions > 10, it calculates `((16 * (byte - position + 1)) | ((byte - position + 1) >> 4)) ^ 0x7A`
3. For bytes at even positions, it applies additional transformations involving bit operations and nibble swapping
4. A special case for the byte at position 4, where the final calculation is `74 - result`
5. For all other positions, the final result is `position + result + 45`

The transformed input is then compared against a hardcoded expected value. By identifying this expected value in the disassembly, we can work backwards to determine the original input:

```
.text:0040101A C7 44 24 0C CA B1 CA A7                 mov     dword ptr [esp+0Ch], 0A7CAB1CAh
.text:00401022 8D 4C 24 0C                             lea     ecx, [esp+0Ch]
.text:00401026 C7 44 24 10 B1 CB D2 B7                 mov     dword ptr [esp+10h], 0B7D2CBB1h
.text:0040102E 8B C7                                   mov     eax, edi
.text:00401030 C7 44 24 14 E1 8F BF 26                 mov     dword ptr [esp+14h], 26BF8FE1h
.text:00401038 C7 44 24 18 32 A6 27 DB                 mov     dword ptr [esp+18h], 0DB27A632h
.text:00401040 C7 44 24 1C 2E CC DC 98                 mov     dword ptr [esp+1Ch], 98DCCC2Eh
.text:00401048 C7 44 24 20 61 51 5C 03                 mov     dword ptr [esp+20h], 35C5161h
.text:00401050 C7 44 24 24 85 E4 84 47                 mov     dword ptr [esp+24h], 4784E485h
.text:00401058 C7 44 24 28 B9 45 B3 75                 mov     dword ptr [esp+28h], 75B345B9h
.text:00401060 C7 44 24 2C 76 FC AB 2E                 mov     dword ptr [esp+2Ch], 2EABFC76h
.text:00401068 C7 44 24 30 72 1B 6C B2                 mov     dword ptr [esp+30h], 0B26C1B72h
.text:00401070 C7 44 24 34 AA 94 C3 42                 mov     dword ptr [esp+34h], 42C394AAh
.text:00401078 C7 44 24 38 C5 23 DC EA                 mov     dword ptr [esp+38h], 0EADC23C5h
.text:00401080 2B C1                                   sub     eax, ecx
.text:00401082 74 2A                                   jz      short loc_4010AE
.text:00401084 50                                      push    eax
.text:00401085 B9 BC 54 40 00                          mov     ecx, offset dword_4054BC
.text:0040108A E8 81 0D 00 00                          call    sub_401E10
.text:0040108F 8B 35 BC 54 40 00                       mov     esi, ds:dword_4054BC
```

From this assembly code, I was able to extract the expected ciphertext: `cab1caa7b1cbd2b7e18fbf2632a627db2eccdc9861515c0385e48447b945b37576fcab2e721b6cb2aa94c342c523dcea`

To recover the original flag, I needed to reverse the transformation process. After analyzing the operations, I created a Python script to invert each step:

```py
def swap_nibbles(b):  # self-inverse
    return ((b << 4) | (b >> 4)) & 0xFF

def rol(b, r):
    r &= 7
    return ((b << r) | (b >> (8 - r))) & 0xFF

def ror(b, r):
    r &= 7
    return ((b >> r) | (b << (8 - r))) & 0xFF

def invert_byte(i, y):
    # undo final add
    if i == 4:
        t = (74 - y) & 0xFF
    else:
        t = (y - (i + 45)) & 0xFF

    # undo even-index twist
    if (i & 1) == 0:
        # t = swap_nibbles(u), u = ROL2(~t0)
        u  = swap_nibbles(t)
        a  = ror(u, 2)           # a = ROR2(u) = ~t0
        t0 = (~a) & 0xFF
    else:
        t0 = t

    # undo first stage
    if i <= 10:
        w = (t0 + 5) & 0xFF
        if (w & 1) == 0:
            d = (w >> 1) & 0x7F               # d in [0..127]
        else:
            d = ((w - 1) >> 1) + 128          # d in [128..255]
        x = (d + i) & 0xFF
    else:
        d = swap_nibbles(t0 ^ 0x7A)
        x = (d - 1 + i) & 0xFF

    return x

ct = bytes.fromhex('cab1caa7b1cbd2b7e18fbf2632a627db2eccdc9861515c0385e48447b945b37576fcab2e721b6cb2aa94c342c523dcea')

plain = bytes(invert_byte(i, b) for i, b in enumerate(ct))
print(plain.decode())
```
