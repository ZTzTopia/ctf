---
title: Simple Math
categories: Reverse Engineering
tags: 
completedDuringEvent: true
submitted: true
flags: flag: ARA6{8yT3_c0d3_W1Th_51MPl3_m4th_15_345Y____R19ht?}
draft: false
---
## Scenario

> "Python is a high-level, general-purpose programming language. Its design philosophy emphasizes code readability with the use of significant indentation."

By Haalloobim

## Solution

```
  0           0 RESUME                   0

  2           2 LOAD_CONST               9 ((5,))
              4 LOAD_CONST               1 (<code object conv at 0x000001D2B5453870, file "<string>", line 2>)
              6 MAKE_FUNCTION            1 (defaults)
              8 STORE_NAME               0 (conv)

  6          10 PUSH_NULL
             12 LOAD_NAME                1 (open)
             14 LOAD_CONST               2 ('flag.txt')
             16 CALL                     1
             24 LOAD_ATTR                5 (NULL|self + read)
             44 CALL                     0
             52 STORE_NAME               3 (flag)

  7          54 BUILD_LIST               0
             56 STORE_NAME               4 (flags)

  8          58 BUILD_LIST               0
             60 LOAD_CONST               3 ((412881107802, 397653008560, 378475773842, 412107467700, 410815948500, 424198405792, 379554633200, 404975010927, 419449858501, 383875726561))
             62 LIST_EXTEND              1
             64 STORE_NAME               5 (N)

  9          66 PUSH_NULL
             68 LOAD_NAME                6 (reversed)
             70 LOAD_NAME                5 (N)
             72 CALL                     1
             80 STORE_NAME               7 (NR)

 11          82 PUSH_NULL
             84 LOAD_NAME                8 (len)
             86 LOAD_NAME                3 (flag)
             88 CALL                     1
             96 LOAD_CONST               0 (5)
             98 BINARY_OP                6 (%)
            102 LOAD_CONST               4 (0)
            104 COMPARE_OP              40 (==)
            108 POP_JUMP_IF_TRUE         2 (to 114)
            110 LOAD_ASSERTION_ERROR
            112 RAISE_VARARGS            1

 13     >>  114 PUSH_NULL
            116 LOAD_NAME                9 (zip)
            118 PUSH_NULL
            120 LOAD_NAME                0 (conv)
            122 LOAD_NAME                3 (flag)
            124 CALL                     1
            132 LOAD_NAME                5 (N)
            134 LOAD_NAME                7 (NR)
            136 CALL                     3
            144 GET_ITER
        >>  146 FOR_ITER                71 (to 292)
            150 UNPACK_SEQUENCE          3
            154 STORE_NAME              10 (i)
            156 STORE_NAME              11 (j)
            158 STORE_NAME              12 (k)

 14         160 LOAD_NAME               13 (int)
            162 LOAD_ATTR               29 (NULL|self + from_bytes)
            182 LOAD_NAME               10 (i)
            184 LOAD_ATTR               31 (NULL|self + encode)
            204 CALL                     0
            212 LOAD_CONST               5 ('big')
            214 CALL                     2
            222 STORE_NAME              16 (x)

 15         224 LOAD_NAME               16 (x)
            226 LOAD_NAME               11 (j)
            228 BINARY_OP                0 (+)
            232 LOAD_CONST               6 (1337)
            234 BINARY_OP                5 (*)
            238 LOAD_NAME               12 (k)
            240 BINARY_OP               12 (^)
            244 STORE_NAME              17 (y)

 16         246 LOAD_NAME               17 (y)
            248 LOAD_CONST               7 (871366131)
            250 BINARY_OP               23 (-=)
            254 STORE_NAME              17 (y)

 17         256 LOAD_NAME                4 (flags)
            258 LOAD_ATTR               37 (NULL|self + append)
            278 LOAD_NAME               17 (y)
            280 CALL                     1
            288 POP_TOP
            290 JUMP_BACKWARD           73 (to 146)

 13     >>  292 END_FOR

 19         294 PUSH_NULL
            296 LOAD_NAME               19 (print)
            298 LOAD_NAME                4 (flags)
            300 CALL                     1
            308 POP_TOP
            310 RETURN_CONST             8 (None)

Disassembly of <code object conv at 0x000001D2B5453870, file "<string>", line 2>:
  2           0 RETURN_GENERATOR
              2 POP_TOP
              4 RESUME                   0

  3           6 LOAD_GLOBAL              1 (NULL + range)
             16 LOAD_CONST               1 (0)
             18 LOAD_GLOBAL              3 (NULL + len)
             28 LOAD_FAST                0 (str)
             30 CALL                     1
             38 LOAD_FAST                1 (l)
             40 CALL                     3
             48 GET_ITER
        >>   50 FOR_ITER                12 (to 78)
             54 STORE_FAST               2 (i)

  4          56 LOAD_FAST                0 (str)
             58 LOAD_FAST                2 (i)
             60 LOAD_FAST                2 (i)
             62 LOAD_FAST                1 (l)
             64 BINARY_OP                0 (+)
             68 BINARY_SLICE
             70 YIELD_VALUE              1
             72 RESUME                   1
             74 POP_TOP
             76 JUMP_BACKWARD           14 (to 50)

  3     >>   78 END_FOR
             80 RETURN_CONST             0 (None)
        >>   82 CALL_INTRINSIC_1         3 (INTRINSIC_STOPITERATION_ERROR)
             84 RERAISE                  1
```

Decompiling the python bytecode, we can see that the flag is being read from a file called `flag.txt` and then converted into a list of integers. The list of integers is then reversed and iterated over. Each integer is converted into a big-endian byte string, which is then added to the next integer multiplied by 1337 and then XORed with the next integer. The result is then subtracted from 871366131 and appended to a list. Finally, the list is printed.

```python
from typing import List

def conv(str: str, l: int) -> List[int]:
    return [int(str[i:i+l], 16) for i in range(0, len(str), l)]

with open('flag.txt') as f:
    flag = f.read().strip()

flags = []
N = [412881107802, 397653008560, 378475773842, 412107467700, 410815948500, 424198405792, 379554633200, 404975010927, 419449858501, 383875726561]
NR = list(reversed(N))

assert len(flag) % 5 == 0

for i, j, k in zip(conv(flag, 5), N, NR):
    x = int(i.encode('big'))
    y = x + j * 1337 ^ k
    y -= 871366131
    flags.append(y)

print(flags)
```

We need to reverse the operations to get the flag. We can do this by first adding 871366131 to each element in the list, then XORing with the next element, then dividing by 1337 and finally converting the result to a big-endian byte string.

```python
N = [412881107802, 397653008560, 378475773842, 412107467700, 410815948500, 424198405792, 379554633200, 404975010927, 419449858501, 383875726561]
NR = list(reversed(N))

flags = [927365724618649, 855544946535839, 1075456339888851, 1051300489856216, 854566738228717, 862564607600557, 1107196607637040, 835104762026329, 1108826984434051, 843310935687105]
flag = ""

# Reverse the process to retrieve original flag
for y, j, k in zip(flags, N, NR):
    y += 871366131  # Reverse adjustment
    x = (y ^ k) // 1337 - j  # Reverse operations
    flag += x.to_bytes(5, 'big').decode(errors='ignore')

print(flag)
```
