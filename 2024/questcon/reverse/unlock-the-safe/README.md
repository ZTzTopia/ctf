---
title: "Unlock the Safe"
categories: "Reverse Engineering"
tags: 
draft: false
completedDuringEvent: true
submitted: true
flag: QUESTCON{pl3as3_l3t_m3_1nt0_th3_saf3}
---
## Scenario

> You’ve lost the key to your digital safe, but there’s a program available to help retrieve it. The program uses a password, but instead of comparing it directly, it encodes the input into Base64 and compares the result with a hardcoded Base64-encoded string. Your task is to figure out the correct password by analyzing how the program processes the input. Once you discover the correct password, you’ll need to format it into the correct CTF flag format to unlock the safe.
>
> Example: QUESTCON{password_to_the_safe}

## Solution

The challenge provides a file named `safeopener.java` which is a Java program. The program is just normal Java code. But inside it there is a hardcoded Base64-encoded string that the program will compare with the Base64-encoded input. The program will then prompt for a password and encode the input into Base64 and compare it with the hardcoded Base64-encoded string.

```java
String encodedkey = "cGwzYXMzX2wzdF9tM18xbnQwX3RoM19zYWYz";
```

The hardcoded Base64-encoded string is `cGwzYXMzX2wzdF9tM18xbnQwX3RoM19zYWYz`. We can decode the Base64-encoded string to get the password. We can use [From Base64](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)&input=Y0d3ellYTXpYMnd6ZEY5dE0xOHhiblF3WDNSb00xOXpZV1l6) to decode the Base64-encoded string.
