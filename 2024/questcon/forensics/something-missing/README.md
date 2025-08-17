---
title: "Something Missing?"
category: Forensics
tags: 
draft: false
completedDuringEvent: true
submitted: true
flag: QUESTCON{H1dd3n_s0_y0u_can1_s33}
---
## Scenario

> Professor got an image from Raquel, but the Intelligence did something!

## Solution

The challenge provides a file named `SomethingMissing` which is a PNG image. The file is corrupted and cannot be opened. The file is missing the PNG header. The PNG header is `89 50 4E 47 0D 0A 1A 0A`. We can add the header to the file using a hex editor. We can use the [Hex Editor](https://hexed.it/) to add the header to the file. After adding the header, we can rename the file to `SomethingMissing.png`. We can now open the file and view the flag.

![SomethingMissing.png](SomethingMissing.png)
