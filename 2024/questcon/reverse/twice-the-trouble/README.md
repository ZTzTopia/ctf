---
title: "Twice the Trouble"
categories: "Reverse Engineering"
tags: 
draft: true
completedDuringEvent: true
submitted: true
flag: QUESTCON{d0ubl3_tr0ubl3}
---
## Scenario

> The Professor has hidden a secret within a simple number comparison script. Two numbers, a special condition, and a flag locked behind encryption. The trick is to trigger the hidden logic—if you can find it.
>
> Solve the puzzle, decrypt the flag, and prove yourself. Can you outsmart the Professor, or will this be twice the trouble?

## Solution

The challenge provides a file named `magnitude.py` which is a Python script. The script is just normal Python code. But inside it there is a function called `get_flag` which contains the flag XORed using the key `13` which we can directly call the function to get the flag.

```python
if __name__ == "__main__":
    print(get_flag())
    main()
```
