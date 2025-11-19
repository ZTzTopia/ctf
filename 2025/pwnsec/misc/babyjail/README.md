---
title: Babyjail()
categories: Miscellaneous
authors: Muhammed
tags: 
draft: false
completedDuringEvent: true
submitted: true
points: 295
solves: 41
flags: flag{RANDOM_EACH_INSTANCE?}
---

> Python Jail() .

---

The challenge provided a python jail environment where we can input some python code to be evaluated. However, there were several restrictions in place to prevent us from executing arbitrary code.

```py
#!/usr/local/bin/python3
import string
import re


UNALLOWED = [
    "ArithmeticError(",
    "AssertionError(",
    "AttributeError(",
    "BaseException(",
    "BaseExceptionGroup(",
    "BlockingIOError(",
    "BrokenPipeError(",
    "BufferError(",
    "BytesWarning(",
    "ChildProcessError(",
    "ConnectionAbortedError(",
    "ConnectionError(",
    "ConnectionRefusedError(",
    "ConnectionResetError(",
    "DeprecationWarning(",
    "EOFError(",
    "Ellipsis(",
    "EncodingWarning(",
    "EnvironmentError(",
    "Exception(",
    "ExceptionGroup(",
    "False(",
    "FileExistsError(",
    "FileNotFoundError(",
    "FloatingPointError(",
    "FutureWarning(",
    "GeneratorExit(",
    "IOError(",
    "ImportError(",
    "ImportWarning(",
    "IndentationError(",
    "IndexError(",
    "InterruptedError(",
    "IsADirectoryError(",
    "KeyError(",
    "KeyboardInterrupt(",
    "LookupError(",
    "MemoryError(",
    "ModuleNotFoundError(",
    "NameError(",
    "None(",
    "NotADirectoryError(",
    "NotImplemented(",
    "NotImplementedError(",
    "OSError(",
    "OverflowError(",
    "PendingDeprecationWarning(",
    "PermissionError(",
    "ProcessLookupError(",
    "RecursionError(",
    "ReferenceError(",
    "ResourceWarning(",
    "RuntimeError(",
    "RuntimeWarning(",
    "StopAsyncIteration(",
    "StopIteration(",
    "SyntaxError(",
    "SyntaxWarning(",
    "SystemError(",
    "SystemExit(",
    "TabError(",
    "TimeoutError(",
    "True(",
    "TypeError(",
    "UnboundLocalError(",
    "UnicodeDecodeError(",
    "UnicodeEncodeError(",
    "UnicodeError(",
    "UnicodeTranslateError(",
    "UnicodeWarning(",
    "UserWarning(",
    "ValueError(",
    "Warning(",
    "WindowsError(",
    "ZeroDivisionError(",
    "__build_class__(",
    "__debug__(",
    "__doc__(",
    "__import__(",
    "__loader__(",
    "__name__(",
    "__package__(",
    "__spec__(",
    "abs(",
    "aiter(",
    "all(",
    "anext(",
    "any(",
    "ascii(",
    "bin(",
    "bool(",
    "breakpoint(",
    "bytearray(",
    "bytes(",
    "callable(",
    "chr(",
    "classmethod(",
    "compile(",
    "complex(",
    "copyright(",
    "credits(",
    "delattr(",
    "dict(",
    "dir(",
    "divmod(",
    "enumerate(",
    "eval(",
    "exec(",
    "exit(",
    "filter(",
    "float(",
    "format(",
    "frozenset(",
    "getattr(",
    "globals(",
    "hasattr(",
    "hash(",
    "help(",
    "hex(",
    "id(",
    "input(",
    "int(",
    "isinstance(",
    "issubclass(",
    "iter(",
    "len(",
    "license(",
    "list(",
    "locals(",
    "map(",
    "max(",
    "memoryview(",
    "min(",
    "next(",
    "object(",
    "oct(",
    "open(",
    "ord(",
    "pow(",
    "print(",
    "property(",
    "quit(",
    "range(",
    "repr(",
    "reversed(",
    "round(",
    "set(",
    "setattr(",
    "slice(",
    "sorted(",
    "staticmethod(",
    "str(",
    "sum(",
    "super(",
    "tuple(",
    "type(",
    "vars(",
    "zip("
]

ALLOWED_CHARS = string.ascii_lowercase+ "_.()"

code = input("code > ")

for char in code:
    if char not in ALLOWED_CHARS:
        print(f"NO")
        exit()

for word in ["import", "os", "system", "flag"] + UNALLOWED:
    if word in code:
        print(f"NO")
        exit()

if len(code) > 21:
    print(f"NO")
    exit()
    
if re.search(r'\((?=[^)]*[a-zA-Z_])[^)]*\)', code):
    print("NO")
    exit()

eval(code)
```

So they just basically blacklisted built-in python functions and some keywords. The allowed characters are only lowercase letters, underscore, dot and parentheses. Since underscore is allowed, we can access hidden attributes of objects. For example, we can access like `__class__` to get the class of an object.

There is hidden attribute `__call__` for functions, which allows us to call the function directly. So we can call the `breakpoint` function like this: `breakpoint.__call__()`. This will drop us into a pdb shell. From there, we can use the `import` statement to import the `os` module and then use `os.system` to read the flag file.

```sh
code > breakpoint.__call__()
> /path/<stdin>-1(1)<module>()
-> import platform
(Pdb) import os; os.system('cat /f*')
```
