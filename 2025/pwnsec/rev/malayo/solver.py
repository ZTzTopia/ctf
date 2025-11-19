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
