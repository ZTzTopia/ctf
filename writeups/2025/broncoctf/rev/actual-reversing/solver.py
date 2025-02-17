import math

# The TRUTH string used in the C program
TRUTH = "Can birds even understand me?"

# Compute the list T of bit positions (0-indexed) in TRUTH that are 1.
# Note: The code checks bits in each char with: (TRUTH[k//8] & (1 << (k % 8)))
T = []
for k in range(8 * len(TRUTH)):
    if (ord(TRUTH[k // 8]) >> (k % 8)) & 1:
        T.append(k)

# Log output differences from the program (d[j] = T[j] - input_bit_position)
log_d = [
    -1, -4, 0, -1, 1, 1, 3, 2, 2, 3, 3, 8, 11, 12, 12, 13, 14, 15, 14, 16,
    15, 15, 14, 17, 19, 19, 19, 19, 20, 20, 19, 25, 27, 28, 28, 26, 28, 28,
    28, 28, 26, 27, 25, 27, 26, 28, 28, 27, 28, 26, 32, 31, 30, 31, 31, 30,
    31, 30, 30, 29, 28, 29, 31, 28, 27, 28, 29, 29, 31, 33, 33, 32, 32, 32,
    32, 32, 29, 32, 33, 32, 32, 28, 32, 30, 31, 30, 30, 31, 30, 33, 35, 33,
    39, 37, 37, 37, 37, 37, 38, 39, 41, 41, 40, 39, 39, 39, 39, 39
]

# if len(log_d) > len(T):
#     raise ValueError("Log length exceeds number of available set bits in TRUTH.")

# Invert the equation: for each set input bit, b[j] = T[j] - d[j]
b_positions = []
for j, d in enumerate(log_d):
    b_j = T[j] - d
    if b_j < 0:
        raise ValueError(f"Invalid: computed negative bit position for index {j}.")
    b_positions.append(b_j)

# (Optional) Check that the positions are strictly increasing
# for i in range(1, len(b_positions)):
#     if b_positions[i] <= b_positions[i-1]:
#         raise ValueError("Bit positions are not strictly increasing; something is wrong.")

# Determine required length (in bits) for the input:
max_bit = max(b_positions)
num_bytes = math.ceil((max_bit + 1) / 8)

# Create an array of bytes (initialize with zeros)
input_bytes = [0] * num_bytes

# Set the computed bits
for pos in b_positions:
    byte_index = pos // 8
    bit_index = pos % 8
    input_bytes[byte_index] |= (1 << bit_index)

# Convert byte array to string
recovered_input = ''.join(chr(b) for b in input_bytes)

print("Recovered input string:")
print(recovered_input)
print("\nInput bytes (hex):")
print(' '.join(f"{b:02x}" for b in input_bytes))
