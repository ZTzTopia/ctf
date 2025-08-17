---
title: "Visual Heist"
categories: Cryptography
tags: 
draft: false
completedDuringEvent: true
submitted: true
flags: flag: QUESTCON{CRYPT70N}
---
## Scenario

> Challenge Description: "Money Heist - Visual Cryptography Heist"
>
> In this challenge, the notorious Professor has developed a highly secure communication technique using Visual Cryptography to hide critical information about the next heist. Your task is to uncover the secret message that holds the exact plan for the heist by decrypting two visually scrambled images.
>
> Scenario: The Professor has left behind two seemingly random images—one labeled "layer1.png" and another called "layer2.png." Both images seem incomprehensible at first glance, but together, they contain the key to the highly confidential heist plan.
>
> Your mission is to use Visual Cryptography to decrypt these images and reveal the hidden message that the Professor encoded.
>
> QUESTCON{HIDDENMESSAGEHERE}

## Solution

The challenge provides a file named `layer1.png` and `layer2.png` which is a PNG image each. The images are visually scrambled and contain the hidden message.

![layer1.png](layer1.png)
![layer2.png](layer2.png)

```sh
ffmpeg -i layer1.png -i layer2.png -filter_complex "overlay=0:0" -codec:a copy output.png
```

The above command will overlay the two images and create a new image named `output.png`. The new image will contain the hidden message.

![output.png](output.png)
