import os

filename = 'flag.enc'

def srand(seed):
    global current_seed
    current_seed = seed - 1

def rand():
    global current_seed
    current_seed = (0x5851F42D4C957F2D * current_seed + 1) & 0xFFFFFFFFFFFFFFFF
    return current_seed >> 33

mod_time = int(os.path.getmtime(filename))
srand(mod_time)

f = open(filename, 'rb')
content = f.read()

flag = bytearray()
for byte in content:
    flag.append(byte ^ (rand() % 127))

print(f'Flag: {"".join(map(chr, flag))}')
