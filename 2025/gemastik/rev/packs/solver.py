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
