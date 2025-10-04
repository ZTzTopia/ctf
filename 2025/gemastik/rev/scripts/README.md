---
title: Scripts
categories: "Reverse Engineering"
authors: aimardcr
tags: 
draft: false
completedDuringEvent: true
submitted: true
points: 0
solves: 0
flags: GEMASTIK18{ez_scripting_language}
---

> Scripting != Coding (or is it?)

---

In this challenge, we are given a binary that validates flag input through a custom scripting system. The binary implements a Lua-like environment with defined operations to check whether our input matches the expected flag.

Examining the main checking function, we can see that the program reads our input, initializes a scripting context, and runs a validation script:

```c
__int64 __fastcall sub_402056(__int64 a1, int a2, int a3, int a4, int a5, int a6)
{
  int v6; // edx
  int v7; // ecx
  int v8; // r8d
  int v9; // r9d
  __int64 result; // rax
  int i; // [rsp+Ch] [rbp-44h]
  int j; // [rsp+10h] [rbp-40h]
  __int64 v14; // [rsp+18h] [rbp-38h]
  _BYTE v15[40]; // [rsp+20h] [rbp-30h] BYREF
  unsigned __int64 v16; // [rsp+48h] [rbp-8h]

  v16 = __readfsqword(0x28u);
  sub_44C870((unsigned int)"Flag: ", a2, a3, a4, a5, a6);
  sub_44C7A0((unsigned int)"%s", (unsigned int)v15, v6, v7, v8, v9);
  if ( j_ifunc_46ECC0() == 33 )
  {
    for ( i = 0; i <= 1162; ++i )
    {
      if ( byte_54CC00[i] == 42 )
      {
        for ( j = 0; j <= 32; ++j )
          byte_54CC00[i + j] = v15[j];
        break;
      }
    }
    v14 = sub_41C650(v15);
    if ( v14 )
    {
      sub_41C730(v14);
      sub_403B70(v14, sub_401F24, 0);
      sub_404380(v14, &byte_54CBA0);
      sub_403B70(v14, sub_401F8A, 0);
      sub_404380(v14, &byte_54CBC0);
      sub_403B70(v14, sub_401FF0, 0);
      sub_404380(v14, &byte_54CBE0);
      if ( (unsigned int)sub_41B6F0(v14, byte_54CC00) || (unsigned int)sub_404A40(v14, 0, 0xFFFFFFFFLL, 0, 0, 0) )
      {
        sub_411090(v14);
        result = 1;
      }
      else
      {
        sub_411090(v14);
        result = 0;
      }
    }
    else
    {
      result = 1;
    }
  }
  else
  {
    sub_45C920("WRONG");
    result = 1;
  }
  if ( v16 != __readfsqword(0x28u) )
    sub_492140();
  return result;
}
```

The main validation logic consists of:

1. Prompting the user for a flag input
2. Checking that the input is exactly 33 characters long
3. Inserting the user input into a script at a position marked by an asterisk (`*`)
4. Initializing a scripting context and registering custom operations
5. Running the validation script and checking if the result is correct

Looking at the initialization function reveals that the program performs XOR decoding of the script and operation names:

```c
void *sub_402277()
{
  void *result; // rax
  int i; // [rsp+0h] [rbp-30h]
  int j; // [rsp+4h] [rbp-2Ch]
  int k; // [rsp+8h] [rbp-28h]
  int m; // [rsp+Ch] [rbp-24h]

  for ( i = 0; i <= 1162; ++i )
    byte_54CC00[i] = byte_4E9040[i] ^ 0xA0;
  byte_54D08B = 0;
  for ( j = 0; j <= 4; ++j )
    byte_54CBA0[j] = byte_4E94CC[j] ^ 0xA0;
  byte_54CBA5 = 0;
  for ( k = 0; k <= 4; ++k )
    byte_54CBC0[k] = byte_4E94D2[k] ^ 0xA0;
  byte_54CBC5 = 0;
  result = byte_4E94D8;
  for ( m = 0; m <= 4; ++m )
  {
    result = (void *)m;
    byte_54CBE0[m] = byte_4E94D8[m] ^ 0xA0;
  }
  byte_54CBE5 = 0;
  return result;
}
```

The program XORs each byte with `0xA0` to decrypt the script and the names of three operations that will be used during validation.

After decoding `byte_4E9040`, we can see the Lua script responsible for flag validation:

```lua
ops = {"j3s5l", "j3s5l", "m9kp2", "qwx7z", "qwx7z", "m9kp2", "j3s5l", "j3s5l", "qwx7z", "j3s5l", "j3s5l", "qwx7z", "m9kp2", "j3s5l", "qwx7z", "j3s5l", "m9kp2", "j3s5l", "j3s5l", "m9kp2", "m9kp2", "qwx7z", "j3s5l", "m9kp2", "j3s5l", "m9kp2", "m9kp2", "j3s5l", "m9kp2", "qwx7z", "qwx7z", "qwx7z", "qwx7z"} 
k = {143, 193, 38, 93, 97, 13, 149, 22, 102, 163, 38, 84, 55, 157, 130, 12, 65, 133, 194, 3, 9, 162, 198, 41, 77, 20, 55, 76, 17, 192, 207, 104, 163}

pt = "*********************************" 
ct = {200, 132, 39, 158, 180, 71, 220, 93, 151, 155, 93, 185, 67, 194, 245, 111, 49, 236, 178, 113, 96, 272, 161, 54, 33, 77, 55, 43, 100, 289, 310, 205, 288} 
for i = 1, #pt do 
  local op_name = ops[i] 
  local key_val = k[i] 
  local char_code = string.byte(pt, i) 
  local result = 0 
  
  if op_name == "qwx7z" then 
    result = qwx7z(char_code, key_val) 
  elseif op_name == "m9kp2" then 
    result = m9kp2(char_code, key_val) 
  elseif op_name == "j3s5l" then 
    result = j3s5l(char_code, key_val) 
  end 
  
  if result ~= ct[i] then 
    print("WRONG") os.exit(1) 
  end 
end 

print("CORRECT") 
```

The script shows:

- An array of operation names (`ops`) to be applied to each character
- A key array (`k`) with values to be used in each operation
- The user input (`pt`) which is initially filled with asterisks but gets replaced with our input
- A target ciphertext array (`ct`) containing the expected results

For each character in our input, the script:

1. Gets the corresponding operation name from the `ops` array
2. Gets the corresponding key value from the `k` array
3. Applies the operation to our input character using the key value
4. Compares the result with the expected value in the `ct` array
5. Exits with "WRONG" if any comparison fails

By examining the code that registers these operations with the Lua environment:

```c
sub_41C730(v14);
sub_403B70(v14, sub_401F24, 0);
sub_404380(v14, &byte_54CBA0);
sub_403B70(v14, sub_401F8A, 0);
sub_404380(v14, &byte_54CBC0);
sub_403B70(v14, sub_401FF0, 0);
sub_404380(v14, &byte_54CBE0);
```

We can determine the three operations:

- `qwx7z(a, b)`: Performs subtraction `a - b`
- `m9kp2(a, b)`: Performs addition `a + b`
- `j3s5l(a, b)`: Performs bitwise XOR `a ^ b`

To find the correct flag, we need to reverse the operations. For each position, we can determine the original character by applying the inverse of the operation:

```py
ops = [ 'j3s5l', 'j3s5l', 'm9kp2', 'qwx7z', 'qwx7z', 'm9kp2', 'j3s5l', 'j3s5l', 'qwx7z', 'j3s5l', 'j3s5l', 'qwx7z', 'm9kp2', 'j3s5l', 'qwx7z', 'j3s5l', 'm9kp2', 'j3s5l', 'j3s5l', 'm9kp2', 'm9kp2', 'qwx7z', 'j3s5l', 'm9kp2', 'j3s5l', 'm9kp2', 'm9kp2', 'j3s5l', 'm9kp2', 'qwx7z', 'qwx7z', 'qwx7z', 'qwx7z' ]
k = [ 143, 193, 38, 93, 97, 13, 149, 22, 102, 163, 38, 84, 55, 157, 130, 12, 65, 133, 194, 3, 9, 162, 198, 41, 77, 20, 55, 76, 17, 192, 207, 104, 163 ]
ct = [ 200, 132, 39, 158, 180, 71, 220, 93, 151, 155, 93, 185, 67, 194, 245, 111, 49, 236, 178, 113, 96, 272, 161, 54, 33, 77, 55, 43, 100, 289, 310, 205, 288 ]

out = []
for o, ki, ci in zip(ops, k, ct): 
    out.append(chr(ci - ki if o == 'qwx7z' else ci + ki if o == 'm9kp2' else ci ^ ki))

print(''.join(out))
```
