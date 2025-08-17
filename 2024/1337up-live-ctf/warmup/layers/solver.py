import os
import base64

path = './layers'

binary_data = ''

for i in sorted(os.listdir(path), key=lambda x: os.path.getmtime(os.path.join(path, x))):
    with open(os.path.join(path, i), 'r') as f:
        binary_data += f.read().strip()

flag = ''.join([chr(int(binary_data[i:i+8], 2)) for i in range(0, len(binary_data), 8)])
print(f'Flag: {base64.b64decode(flag).decode()}')
