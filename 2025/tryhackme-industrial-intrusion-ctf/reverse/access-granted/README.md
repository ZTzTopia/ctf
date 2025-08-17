---
title: Access Granted
categories: Reverse Engineering
tags: 
draft: false
completedDuringEvent: true
submitted: true
points: 30
solves: -1
flag: THM{REDACTED}
---
> ZeroTrace intercepts a suspicious HMI login module on the plant floor. Reverse the binary logic to reveal the access key and slip past digital defences.

---

The binary provided contains a simple password-checking mechanism. The main function reads user input and compares it to a predefined password using the `strncmp` function.

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char buf[40]; // [rsp+0h] [rbp-30h] BYREF
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  printf("Enter the password : ");
  read(0, buf, 0x1FuLL);
  printf("\nprocessing...");
  if ( !strncmp(pass, buf, 0xAuLL) )
  {
    puts("Access Granted!");
    print_flag();
  }
  else
  {
    puts("\nWrong Password!");
  }
  return 0;
}
```

The password is stored in the `.data` section of the binary.

```
.data:0000000000004010                 public pass
.data:0000000000004010 ; char pass[]
.data:0000000000004010 pass            db 'REDACTED',0       ; DATA XREF: main+A0↑o
.data:0000000000004010 _data           ends
.data:0000000000004010
```
