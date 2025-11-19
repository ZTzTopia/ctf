---
title: Malayo
categories: "Revese Engineering"
authors: w3rty
tags: 
draft: false
completedDuringEvent: true
submitted: true
points: 100
solves: 101
flags: flag{U_K33p_1t_th4t_w4y_0r_L34v3_1t}
---

> Under the sound of the wild, The Malayopython appears

---

So this challenge provides us with a `.pyc` file that we can decompile by using `pylingual` or other decompilers. After decompiling by `pylingual`, we get some like reconstructed bytecode, which is some of function is failing to decompile properly. However, we can still use the original bytecode to reconstruct by using ChatGPT or other LLMs. After reconstructing, we get the following code:

```py
def Uu(f):
    try:
        if f[0] != 102: return False    # 'f'
        if f[1] != 108: return False    # 'l'
        if f[2] != 97:  return False    # 'a'
        if f[3] != 103: return False    # 'g'
        if f[4] != 123: return False    # '{'
        if f[5] != 85:  return False    # 'U'
        if f[6] != 95:  return False    # '_'
        return True
    except:
        return False

def uU(f):
    try:
        # f[7]*7 - 525 == 0
        if f[7] * 7 != 525: return False   # f[7] = 75 ('K')

        # f[8]*17 - 10 XOR 933 == 252
        if ((f[8] * 17 - 10) ^ 933) != 252: return False

        # three squared-diff sums = 0
        if ((f[9] - f[8])**2 +
            (f[28] - f[8])**2 +
            (f[31] - f[8])**2) != 0:
            return False

        # (f[10] -112)*1000 + (f[11] - 95) == 0
        if (f[10] - 112) * 1000 + (f[11] - 95) != 0:
            return False

        # big multi squared diff for indices 14,19,23,26,32 relative to f[11]
        base = f[11]
        s11 = ((f[14] - base)**2 +
               (f[19] - base)**2 +
               (f[23] - base)**2 +
               (f[26] - base)**2 +
               (f[32] - base)**2)
        if s11 != 0: return False

        # weird invert check
        if ((~f[12] + 0) ^ -1) - 49 != 0: return False

        # f[33] - f[12] == 0
        if f[33] != f[12]: return False

        # (f[13]+10)*5 XOR 95 == 553
        if ((f[13] + 10) * 5) ^ 95 != 553: return False

        # (f[15] - f[13])**2 + (f[18] - f[13])**2 + (f[34] - f[13])**2 == 0
        if ((f[15] - f[13])**2 +
            (f[18] - f[13])**2 +
            (f[34] - f[13])**2) != 0:
            return False

        return True
    except:
        return False

def UU(f):
    try:
        if f[16]*2 - 12 - 196 != 0: return False    # f[16] = 104 'h'
        if (f[17] << 0) ^ 0 != 52: return False     # f[17] = '4'
        if ((f[21] - f[17])**2 + (f[29] - f[17])**2) != 0: return False
        if 3*f[20] - 357 != 0: return False         # f[20] = 119 'w'
        if f[22] - f[20] - 2 != 0: return False
        if (f[24] ^ 0) - 48 != 0: return False
        if f[25] - (f[22] - 7) != 0: return False
        if (f[27] - 76) * (f[30] - 118) != 0: return False
        return True
    except:
        return False

def UUu(f):
    try:
        flag_content = "".join(chr(c) for c in f[7:35])

        key_part = flag_content[:17]
        key = hashlib.sha256(key_part.encode()).digest()

        plaintext = flag_content[17:]

        expected_ciphertext = base64.b64decode("jNtv1ielcDMRvnTLzB2hrg==")
        iv = b"PWNSEC_CHALLENGE"

        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = pad(plaintext.encode(), AES.block_size)
        if cipher.encrypt(padded) != expected_ciphertext:
            return False

        if sum(f) != 3217:
            return False

        if f[35] != 125: return False   # '}'

        return True
    except:
        return False

def you(user_flag):
    if len(user_flag) != 36:
        return False
    f = list(map(ord, user_flag))
    if not Uu(f): return False
    if not uU(f): return False
    if not UU(f): return False
    if not UUu(f): return False
    return True
```

Now, we can see that the flag length is 36 characters, and there are four functions that validate different parts of the flag. We can use Z3 to solve the constraints given in these functions. Here's a Z3 script that does just that:

```py
from z3 import *

FLAG_LEN = 36

f = [BitVec(f'f[{i}]', 32) for i in range(FLAG_LEN)]
s = Solver()

for b in f:
    s.add(b >= 0, b <= 255)

# Uu
s.add(f[0] == 102)
s.add(f[1] == 108)
s.add(f[2] == 97)
s.add(f[3] == 103)
s.add(f[4] == 123)
s.add(f[5] == 85)
s.add(f[6] == 95)

# uU
s.add(f[7] * 7 == 525)
s.add(((f[8] * 17 - 10) ^ BitVecVal(933, 32)) == 252)

# s.add((f[9] - f[8]) * (f[9] - f[8]) +
#       (f[28] - f[8]) * (f[28] - f[8]) +
#       (f[31] - f[8]) * (f[31] - f[8]) == 0)
s.add(f[9] == f[8])
s.add(f[28] == f[8])
s.add(f[31] == f[8])

s.add((f[10] - 112) * 1000 + (f[11] - 95) == 0)

base = f[11]
# s.add((f[14] - base)*(f[14] - base) +
#       (f[19] - base)*(f[19] - base) +
#       (f[23] - base)*(f[23] - base) +
#       (f[26] - base)*(f[26] - base) +
#       (f[32] - base)*(f[32] - base) == 0)
s.add(f[14] == base)
s.add(f[19] == base)
s.add(f[23] == base)
s.add(f[26] == base)
s.add(f[32] == base)

# s.add(((~f[12]) ^ BitVecVal(-1, 32)) - 49 == 0)
s.add(f[12] == 49)
s.add(f[33] == f[12])

s.add((((f[13] + 10) * 5) ^ BitVecVal(95, 32)) == 553)

# s.add((f[15] - f[13])*(f[15] - f[13]) +
#       (f[18] - f[13])*(f[18] - f[13]) +
#       (f[34] - f[13])*(f[34] - f[13]) == 0)
s.add(f[15] == f[13])
s.add(f[18] == f[13])
s.add(f[34] == f[13])

# UU
s.add(f[16] * 2 - 12 - 196 == 0)
# s.add((f[17] << 0) == 52)
s.add(f[17] == 52)

# s.add((f[21] - f[17])*(f[21] - f[17]) +
#       (f[29] - f[17])*(f[29] - f[17]) == 0)
s.add(f[21] == f[17])
s.add(f[29] == f[17])

s.add(3 * f[20] == 357)
s.add(f[22] == f[20] + 2)
s.add((f[24] ^ BitVecVal(0, 32)) == 48)
s.add(f[25] == f[22] - 7)

s.add(Or(f[27] == 76, f[30] == 118))

# UUu
s.add(Sum([ZeroExt(24, b) for b in f]) == 3217)
s.add(f[35] == ord('}'))

if s.check() == sat:
    m = s.model()
    flag = ''.join(chr(m[f[i]].as_long()) for i in range(FLAG_LEN))
    print("Flag:", flag)
else:
    print("No solution found.")
```
