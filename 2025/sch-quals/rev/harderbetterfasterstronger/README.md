---
title: HarderBetterFasterStronger
categories: "Reverse Engineering"
authors: tsakuyaiba
tags: 
draft: false
completedDuringEvent: true
submitted: true
points: 100
solves: 63
flags: SCH25{Whwn_yhhhh_jwago_revvvvers_semga_nlaimu_AAAA_sellu}
---

> My friend asked me to make a practice problem for the midterm exam. But he said my first one was too easy — not challenging enough. So I rebuilt it to be harder, better, faster, stronger.

---

Open https://chatgpt.com/ -> Switch to IDA Pro -> CTRL + C -> Switch to https://chatgpt.com/ -> CTRL + V: https://chatgpt.com/share/68f394b8-78ec-8001-ad64-d9f349f9beef

```py
def decrypt_from_hex(hex_string):
    data = bytes.fromhex(hex_string)
    key0 = 0x25
    v12 = 0
    out = bytearray()

    for i, b in enumerate(data):
        v14 = v12 ^ (((3 * key0 + 5) << 2) & 0xFF | ((3 * key0 + 5) >> 6))
        v12 = (v12 + 13) & 0xFF
        out.append(b ^ ((v14 - (i & 0xF)) & 0xFF) ^ 6)

    return bytes(out)

print(decrypt_from_hex("849e87c7d2f6c8edc0f3102c2f05376d58674844b0d2908782fb09f3c1f83d46280e0a78604c604bbbdc869892d23ee4e6ec0036123103607a"))
```
