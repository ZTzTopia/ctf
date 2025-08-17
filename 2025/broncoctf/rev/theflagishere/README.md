---
title: theflagishere!
categories: Reverse Engineering
tags: 
draft: false
completedDuringEvent: true
submitted: true
flags: bronco{i_am_a_flag}
---
> So, my friend sent me this program that\u2019s supposed to determine the flag for this challenge, right? But, somehow, they forgot to actually say what the flag is. Classic move. \ud83d\ude02 Now, it\u2019s on you to figure out what the true flag is. If you can crack it and figure out what my friend was trying to send, that flag is all yours! Ready to flex those decoding skills? Let\u2019s get it!

Format: bronco{flag}

By serilical

---

Given a file named `theflagishere.pyc` and a hint that it is a python compiled file, we can use a decompiler to get the source code. I used [pylingual.io](https://pylingual.io/) to decompile the file. 

[https://pylingual.io/view_chimera?identifier=1f1468a7d8ca8cbfa686caa36e17a1a373bb9fb326870e9a78e2655dc7a8fce6](https://pylingual.io/view_chimera?identifier=1f1468a7d8ca8cbfa686caa36e17a1a373bb9fb326870e9a78e2655dc7a8fce6) 

```py
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: theflagishere.py
# Bytecode version: 3.9.0beta5 (3425)
# Source timestamp: 2025-02-13 23:36:18 UTC (1739489778)

def what_do_i_do(whoKnows):
    a_st = {}
    for a in whoKnows:
        if a_st.get(a) == None:
            a_st[a] = 1
        else:
            a_st[a] += 1
    variable_name = 0
    not_a_variable_name = 'None'
    for a in a_st:
        if a_st[a] > variable_name:
            not_a_variable_name = a
            variable_name = a_st[a]
    return (not_a_variable_name, variable_name)

def char_3():
    return 'm'

def i_definitely_return_the_flag():

    def notReal():

        def actually_real():
            return 'actuallyaflag'
        return actually_real

    def realFlag():
        return 'xXx___this__is_the__flag___xXx'
    return (realFlag, notReal)

def i_am_a_function_maybe(param):
    variableName = (param + 102) * 47
    for i in range(0, 100):
        variableName *= i + 1
        variableName /= i + 1
        newVariable = variableName * i
        newVariable += 100
    return chr(ord(chr(int(variableName) + 1)))

def i_do_not_know():
    realFlagHere = 'br0nc0s3c_fl4g5_4r3_345y'
    return 'long_live_long_flags'

def unrelated_statement():
    return 'eggs_go_great_with_eggs'

def i_am_a_function(param):
    variableName = (param + 102) * 47
    for i in range(0, 100):
        variableName *= i + 1
        newVariable = variableName * i
        newVariable += 100
        variableName /= i + 1
    return chr(ord(chr(int(variableName))))

def i_return_a_helpful_function():

    def i_do_something(char):
        var = []
        for i in range(54, 2000):
            var.append(ord(char) / 47 - 102)
        var.reverse()
        return var.pop()
    return i_do_something

def i_return_the_flag():
    return 'thisisdefinitelytheflag!'

def i():
    return 'free_flag_f'

def char_0():
    return i_am_a_function_maybe(i_return_a_helpful_function()(what_do_i_do(i_return_the_flag())[0]))

def char_1_4_6():
    return i_am_a_function_maybe(i_return_a_helpful_function()(what_do_i_do(i_definitely_return_the_flag()[0]())[0]))

def char_2_5_9():
    return i_am_a_function_maybe(i_return_a_helpful_function()(what_do_i_do(i_definitely_return_the_flag()[1]()())[0]))

def char_7():
    return i_am_a_function_maybe(i_return_a_helpful_function()(what_do_i_do(interesting()()()())[0]))

def char_8():
    return i_am_a_function_maybe(i_return_a_helpful_function()(what_do_i_do(i_do_not_know())[0]))

def char_10():
    return i_am_a_function_maybe(i_return_a_helpful_function()(what_do_i_do(unrelated_statement())[0]))

def interesting():

    def notinteresting():

        def veryuninteresting():

            def interesting_call():
                return i
            return interesting_call
        return veryuninteresting
    return notinteresting
```

There are a lot of functions that are not used in the main function. We can ignore them. The main function is `char_0`, `char_1_4_6`, `char_2_5_9`, `char_7`, `char_8`, and `char_10`. We can run these functions to get the flag.

```py
print(f'bronco{{{char_0() + char_1_4_6() + char_2_5_9() + char_3() + char_1_4_6() + char_2_5_9() + char_6() + char_1_4_6() + char_2_5_9() + char_9() + "?" + char_8() + char_10()}}}')
```

Because `char_7` had an error, `***<module>.char_7: Failure: Different bytecode` we need to guess the character for `char_7` which is `f`.
