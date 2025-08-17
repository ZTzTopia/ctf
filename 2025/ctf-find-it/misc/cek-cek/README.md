---
title: cek-cek
categories: Miscellaneous
tags: 
draft: false
completedDuringEvent: true
submitted: true
flags: FindITCTF{cl0s3_y0ur_f1l3s_1mmed14t3ly_0r_w0w0_w1ll_f1nd_y0u}
---
> Hei, aku baru belajar python. Semoga aku tidak melupakan sesuatu.

by `hilmo`

---

We are given a Python script that opens a file we input, and if we choose not to open a file, it reveals the flag (but hashed using `blake2b`).

```py
if __name__ == "__main__":
    with open("/flag.txt", "w") as f:
        f.write(FLAG)

    flag_file = os.open("/flag.txt", os.O_RDONLY)
    flag_data = os.read(flag_file, 1024)

    if FLAG.encode() != flag_data:
        print("flag file is corrupted")
        exit(1)

    while True:
        print("Do you want check my file?")
        print("1. yes")
        print("2. no")

        choice = input(">>> ")
        if choice == "1":
            file_name = input("file name: ")
            print(open_file(file_name))
        elif choice == "2":
            print("ok, here the flag:")
            print(flag)
        else:
            print("invalid choice")
```

Since the file `/flag.txt` is opened and read but never closed, we can exploit this to retrieve the flag. By using `os.open`, we can access the file through `/proc/self/fd`, which is a symbolic link to the file descriptors currently opened by the process. Then, using `os.read`, we can read the contents of the open file descriptor.

By inputting `/proc/self/fd/5` as the filename, we can successfully read and obtain the flag.
