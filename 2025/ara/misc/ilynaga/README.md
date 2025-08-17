---
title: ilynaga
category: Miscellaneous
tags: 
completedDuringEvent: true
submitted: true
flag: ARA6{w4s_1t_h4Rd_0r_N0T_0558d4a}
draft: false
---
## Scenario

> My beloved agent Naga is trying to infiltrate Jerry's Biometrically-secured dewaweb VPS! Help him bypass Jerry's face recognition system!
>
> https://huggingface.co/spaces/spuun/ilynaga

By kek.c

## Solution

The challenge provides a link to a Hugging Face model called `spuun/ilynaga`. The model is a facial recognition model that can be used to authenticate a user's face. The goal is to bypass the facial recognition system to gain access to Jerry's Biometrically-secured dewaweb VPS.

```python
return success if ssim_value>=0.96 and predicted_class == 'True' else fail
```

The model uses the Structural Similarity Index (SSIM) to compare the input image with the reference image. If the SSIM value is greater than or equal to 0.96 and the predicted class is `True`, the authentication is successful.

~~We can bypass the facial recognition system by generating an image that has a high SSIM value with the reference image and a predicted class of `True`?~~

We can bypass the facial recognition system by editing the photo of the reference image to have a high SSIM value with the reference image and a predicted class of `True`.

![alt text](nagaluv2.png)

The edited photo has a high SSIM value with the reference image and a predicted class of `True`. We can use this photo to bypass the facial recognition system. This is unintended solution. The intended solution is to use the model to generate a photo that has a high SSIM value with the reference image and a predicted class of `True`.

```
guest@terminal:~$ ssh jerry@husseumi.space
Connecting to husseumi.space on port 22...

✧ Initiating facial authentication... ✧
⋆｡°✩ Scanning face... ✩°｡⋆
.｡*ﾟ Matching with database... ﾟ*｡.
✧･ﾟ: Biometric verification complete! :･ﾟ✧

╭──── 🌠 Welcome to Jelly's Space 🌠 ─────╮
│   *:･ﾟ✧ Authentication successful! ✧ﾟ･:*  |
│         a-awawawa... welcome back!        │
╰─────────────- ✧◝(⁰▿⁰)◜✧ -────────────╯
Last login: Wed Mar 13 12:34:56 2024 from 192.168.1.1
This server is powered by dewaweb™ - Empowering Your Digital Dreams ⋆｡°✩

jerry@husseumi:~$ cat ~/.auth/metrics.log
⭑⋆˙⟡ Facial Match : True
⭑⋆˙⟡ Match Score : 0.9467
⭑⋆˙⟡ Similarity : 0.9732

jerry@husseumi:~$ sudo cat /etc/secrets/flag.txt
⋆｡°✩ ARA6{w4s_1t_h4Rd_0r_N0T_0558d4a} ✩°｡⋆

jerry@husseumi:~$ exit
✧･ﾟ: A-awawawa... goodbye! Have a lovely day! :･ﾟ✧
.｡*ﾟ+.*.｡(っ°v°c)｡.*+.ﾟ*｡.

Connection to husseumi.space closed.
```
