s = "\ufffa\uffae\uffc5\uffdf\uffda\uff8c\uffbf\uff99\uff93\uff9e\uff98\uff84\uffc8\uff97\uff9a\uffa0\uff9b\uff9a\uff89\uff9a\uff93\uff90\uff8f\uff9a\uff8d\uffa0\uff96\uff8c\uffa0\uffac\uffcf\uffa0\uff8f\uffcb\uff8d\uffcb\uff91\uffcf\uffce\uff9b\uffa0\uffce\uff8b\uffa0\uff8b\uff97\uffce\u0091\u0094\u00ca\u00a0\u00b9\u008d\u00ce\u009b\u00cb\u00a0\u00ce\u008c\u00a0\u00cc\u0089\u00cc\u008d\u0086\u0088\u0097\u00cc\u008d\u00cc\u0082\u00f9\u00b7\u0096\u0091\u008b\u00c5\u00df\u00cf\u00bc\u0097\u009a\u009c\u0094\u00df\u008b\u0097\u009a\u00df\u009e\u008c\u008c\u009a\u008b\u00df\u0099\u0090\u0093\u009b\u009a\u008d\u00d3\u00df\u0086\u0090\u008a\u00df\u0092\u0096\u0098\u0097\u008b\u00df\u0099\u0096\u0091\u009b\u00df\u008c\u0090\u0092\u009a\u008b\u0097\u0096\u0091\u0098\u00fa\u00ae\u00c5\u00df\u00da\u008c"

MASK64 = (1 << 64) - 1

def rotl16(x, n):
    n %= 16
    return ((x << n) & 0xffff) | ((x & 0xffff) >> (16 - n))

def seed(j):
    j &= MASK64
    v0 = (j >> 33) & MASK64
    j ^= v0
    j = (j * 0x62a9d9ed799705f5) & MASK64
    v0 = (j >> 28) & MASK64
    j ^= v0
    j = (j * ((-0x34db2f5a3773ca4d) & MASK64)) & MASK64
    v0 = (j >> 32) & MASK64
    j ^= v0
    return j & MASK64

def next_rand(j):
    j &= MASK64
    mask = 0xffff

    v2 = j & mask
    p0 = (j >> 16) & mask

    p1 = (v2 + p0) & 0xffff
    p1 = rotl16(p1, 9)
    p1 = (p1 + v2) & 0xffff

    p0_xor = p0 ^ v2

    v0 = rotl16(v2, 13)
    v0 ^= p0_xor
    v0 &= 0xffff

    v1 = (p0 << 5) & 0xffff
    v0 ^= v1

    p0 = rotl16(p0, 10)

    high = p1 & 0xffff
    res = ((high << 32) & MASK64) | ((p0 & 0xffff) << 16) | (v0 & 0xffff)
    return res & MASK64

def getCharAt_single(i, s, j):
    rnd = next_rand(j)
    pos = i % len(s)
    c = ord(s[pos]) & 0xffff
    val = (c << 32) ^ rnd
    return val & MASK64

def getString_lowbytes(j, s):
    j &= MASK64
    v = seed(j)

    # derive p0
    v = next_rand(v)
    ushr32 = (v >> 32) & 0xffff
    v = next_rand(v)
    ushr16 = (v >> 16) & 0xffff0000

    p0 = (((j >> 32) & MASK64) ^ ushr32 ^ (ushr16 >> 16)) & 0xffffffff

    # first call gives us length
    val = getCharAt_single(p0, s, j)
    length = (val >> 32) & 0xffff

    out = []
    for k in range(length):
        idx = p0 + k + 1
        val = getCharAt_single(idx, s, j)
        ch = (val >> 32) & 0xffff
        out.append(ch & 0xff)

    return bytes(out)

# candidate 64-bit seeds (from reversing)
keys = [
    -0x7fbb3515ad,
    -0xbb3515ad,
    -0x6bb3515ad,
    -0x47bb3515ad,
    -0x4ebb3515ad,
]

import re

for k in keys:
    j = k & MASK64
    b = getString_lowbytes(j, s)
    print('--- KEY', hex(j), 'LEN', len(b))

    hits = 0
    for key in range(1, 256):
        xb = bytes(c ^ key for c in b)
        if re.search(b'(?i)(ctf|flag)', xb):
            m = re.search(rb'[\x20-\x7e]{8,}', xb)
            if m:
                snippet = m.group(0).decode('ascii', errors='ignore')
            else:
                snippet = xb[:80].hex()
            print('XOR', hex(key), 'FOUND_SNIPPET:', snippet)
            hits += 1

    if hits == 0:
        for m in re.finditer(rb'[\x20-\x7e]{8,}', b):
            print('PLAINTEXT_CAND:', m.group(0).decode('ascii', errors='ignore'))
            break
