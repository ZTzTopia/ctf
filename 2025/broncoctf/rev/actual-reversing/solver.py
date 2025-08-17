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
