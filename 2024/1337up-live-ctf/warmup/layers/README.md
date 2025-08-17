---
title: Layers
categories: Miscellaneous
tags: 
completedDuringEvent: true
submitted: true
flag: INTIGRITI{7h3r35_l4y3r5_70_7h15_ch4ll3n63}
draft: true
---
## Scenario

> Weird way to encode your data, but OK! 🤷‍♂️

By CryptoCat

## Solution
The challenge provides a zip file containing multiple files, each representing a single bit of a binary string. The files are named sequentially as `1`, `2`, `3`, and so on. The objective is to reconstruct the binary string from these files and decode it to retrieve the flag.

Initially, I concatenated the binary strings based on the file names, resulting in the following binary string:

```
2M9NRx5NRVuNVNDzzacsgsVHSUNN9dVJSNbz3fjUjNBIjUdkSfz9eDoS
```

Attempting to base64 decode the string did not yield the flag. Suspecting that the binary string might be reversed, I reversed it and tried decoding again, but it still did not produce the correct flag.

After further analysis, I realized that the binary string should be constructed based on the file modified times rather than the file names. By sorting the files according to their modified times and then concatenating the binary strings, I was able to decode the correct flag.

Here is the Python script used to achieve this:

```python
import os
import base64

path = './layers'

binary_data = ''

for i in sorted(os.listdir(path), key=lambda x: os.path.getmtime(os.path.join(path, x))):
    with open(os.path.join(path, i), 'r') as f:
        binary_data += f.read().strip()

flag = ''.join([chr(int(binary_data[i:i+8], 2)) for i in range(0, len(binary_data), 8)])
print(f'Flag: {base64.b64decode(flag).decode()}')
```

By running the script, the correct flag is obtained.
