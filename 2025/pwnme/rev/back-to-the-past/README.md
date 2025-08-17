---
title: "Back to the past"
category: Reverse Engineering
tags: 
draft: false
completedDuringEvent: true
submitted: true
flag: PWNME{4baf3723f62a15f22e86d57130bc40c3}
---
> Using the provided binary and the encrypted file, find a way to retrieve the flag contained in "flag.enc". Note that the binary would have been run in May 2024. Note: The flag is in the format PWNME{...}
>
> Author : `Fayred`
>
> Flag format: `PWNME{.........................}`

by Fayred

---

The binary uses the current time as a seed for the random number generator. The random number generator is used to generate a key to xor the content of the file `flag.enc`. The key can be recovered by using the same seed as the binary.

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char v3; // cl
  int v5; // edx
  char v6; // cl
  const char *v7; // rsi
  int v8; // edx
  char v9; // cl
  int v10; // eax
  char v11; // cl
  int v13; // [rsp+1Ch] [rbp-124h]
  unsigned int v14; // [rsp+20h] [rbp-120h]
  __int64 v15; // [rsp+28h] [rbp-118h]
  char v16[264]; // [rsp+30h] [rbp-110h] BYREF
  unsigned __int64 v17; // [rsp+138h] [rbp-8h]

  v17 = __readfsqword(0x28u);
  if ( argc > 1 )
  {
    v14 = time(0LL, argv, envp);
    printf((unsigned int)"time : %ld\n", v14, v5, v6);
    srand(v14);
    v7 = "rb+";
    v15 = fopen64(argv[1]);
    if ( v15 )
    {
      while ( 1 )
      {
        v13 = getc(v15, v7);
        if ( v13 == -1 )
          break;
        fseek(v15, -1LL, 1LL);
        v10 = rand();
        v7 = (const char *)v15;
        fputc(v13 ^ (unsigned int)(v10 % 127), v15);
      }
      fclose(v15);
      strcpy(v16, argv[1]);
      strcat(v16, ".enc");
      if ( (unsigned int)rename(argv[1], v16) )
      {
        printf((unsigned int)"Can't rename %s filename to %s.enc", (unsigned int)argv[1], (unsigned int)argv[1], v11);
        return 1;
      }
      else
      {
        return 0;
      }
    }
    else
    {
      printf((unsigned int)"Can't open file %s\n", (unsigned int)argv[1], v8, v9);
      return 1;
    }
  }
  else
  {
    printf((unsigned int)"Usage: %s <filename>\n", (unsigned int)*argv, (_DWORD)envp, v3);
    return 1;
  }
}
```

By examining the binary, we can see that it encrypts a file using the following process:

1. It retrieves the current time (`time(0LL)`) and uses it as a seed for the random number generator (`srand(time)`).
2. It opens the specified file and reads its contents byte by byte.
3. Each byte is XOR-ed with a random number generated using `rand() % 127`.
4. The modified file is saved with the `.enc` extension.

The binary uses a custom implementation of `rand()`:

```c
__int64 __fastcall srand(int a1)
{
  __int64 result; // rax

  result = (unsigned int)(a1 - 1);
  seed = result;
  return result;
}

unsigned __int64 rand()
{
  seed = 0x5851F42D4C957F2DLL * seed + 1;
  return (unsigned __int64)seed >> 33;
}
```

This is a linear congruential generator (LCG). Since the only input to this function is the seed (derived from time).

Since the encryption key is derived from `time(0LL)`, we can determine the exact seed by checking the file's modification time (`os.path.getmtime`). This allows us to reproduce the same random sequence and decrypt the file.

We can implement the decryption process as follows:

```py
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
```
