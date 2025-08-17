---
title: Auth
categories: Reverse Engineering
tags: 
draft: false
completedDuringEvent: true
submitted: true
points: 30
solves: -1
flag: THM{REDACTED}
---
> ZeroTrace intercepts a stripped-down authentication module running on a remote industrial gateway. Assembly scrolls across glowing monitors as she unpacks the logic behind the plant’s digital checkpoint.

---

The challenge revolves around bypassing the authentication logic implemented in the `main` function. The key comparison happens at `memcmp(&s1, &s2, 8uLL)`, where `s1` is derived from user input and `s2` is a hardcoded value `0xEFCDAB8967452301LL`. To pass this check, we need to understand the `transform` function and reverse its logic.

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  FILE *stream; // [rsp+8h] [rbp-168h]
  __int64 s1; // [rsp+10h] [rbp-160h] BYREF
  unsigned __int64 s2; // [rsp+18h] [rbp-158h] BYREF
  char s[64]; // [rsp+20h] [rbp-150h] BYREF
  char v8[264]; // [rsp+60h] [rbp-110h] BYREF
  unsigned __int64 v9; // [rsp+168h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  s2 = 0xEFCDAB8967452301LL;
  printf("[?] Enter unlock code: ");
  if ( fgets(s, 64, _bss_start) )
  {
    s[strcspn(s, "\r\n")] = 0;
    if ( strnlen(s, 0x40uLL) == 8 )
    {
      s1 = *(_QWORD *)s;
      transform(&s1, 8LL);
      if ( !memcmp(&s1, &s2, 8uLL) )
      {
        stream = fopen("flag.txt", "r");
        if ( stream )
        {
          if ( fgets(v8, 256, stream) )
            printf("[+] Access Granted! Flag: %s", v8);
          else
            fwrite("Error reading flag\n", 1uLL, 0x13uLL, stderr);
          fclose(stream);
          return 0;
        }
        else
        {
          perror("fopen");
          return 1;
        }
      }
      else
      {
        puts("[!] Access Denied!");
        return 1;
      }
    }
    else
    {
      puts("[!] Access Denied!");
      return 1;
    }
  }
  else
  {
    fwrite("Error reading input\n", 1uLL, 0x14uLL, stderr);
    return 1;
  }
}
```

The `main` function reads an unlock code from the user, processes it using the `transform` function, and compares the result with the hardcoded value `s2`. If the comparison succeeds, the flag is read from `flag.txt`.

```c
unsigned __int64 __fastcall transform(__int64 a1, unsigned __int64 a2)
{
  unsigned __int64 result; // rax
  unsigned __int64 i; // [rsp+18h] [rbp-8h]

  for ( i = 0LL; ; ++i )
  {
    result = i;
    if ( i >= a2 )
      break;
    *(_BYTE *)(a1 + i) ^= 0x55u;
  }
  return result;
}
```

The `transform` function modifies the input by XORing each byte with `0x55`. This means that to reverse the transformation, we can simply XOR the bytes of the hardcoded value `s2` with `0x55` to get the original input that would pass the `memcmp` check.

To bypass the `memcmp` check, we need to calculate the input that, after being transformed, matches `s2`. This can be achieved by reversing the transformation:

```py
from pwn import *

context.binary = './auth'
context.log_level = 'debug'

# r = process('./auth')
r = remote('10.10.57.42', 9005)

def transform(a1, a2):
    result = bytearray(a1)
    for i in range(a2):
        result[i] ^= 0x55
    return bytes(result)

code = bytes.fromhex('EFCDAB8967452301')[::-1]
decrypted_code = transform(code, 8)

log.info(f'Decrypted code: {decrypted_code.hex()}')
r.sendline(decrypted_code)
r.interactive()
```
