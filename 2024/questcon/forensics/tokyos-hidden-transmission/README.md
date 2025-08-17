---
title: "Tokyo's Hidden Transmission"
categories: Forensics
tags: 
  - audio
  - morse-code
draft: false
completedDuringEvent: true
submitted: true
flags: QUESTCON{morsecodeftw}
---
## Scenario

> Tokyo has left an encrypted message within an audio file, disguised under the noise of a loud, busy background. The file may sound like a regular conversation, but hidden beneath it lies the key to the heist's next move. This transmission is cleverly split into two channels—left and right. The loud audio on the left is just a distraction; the real clue is hidden in the soft, almost imperceptible sound on the right channel.
>
> Mission Objective: Separate the channels and focus on the quieter right channel. Increase the volume, and you will notice something familiar—Morse code. Decipher the hidden message embedded in the dots and dashes to unlock the next stage of the plan. QUESTCON{hiddenmessage} (lowercase!)

## Solution

The challenge provides a file named `tokyo.wav` which is a WAV audio file. This file has two channels, left and right, on the left channel there will be a very noisy sound (song sound) and on the right there is a very quiet sound (hidden sound). We can use FFmpeeg to separate the left and right channels.

```sh
ffmpeg -i tokyo.wav -af "pan=mono|c0=FR" output.wav
```

After separating the left and right channels, we can listen to the output.wav file which is the right channel. There we will hear the hidden sound. That is the sound that gives us the morse code. We can use audacity to increase the volume of the right channel. After increasing the volume, we can hear the morse code. 

```
-- --- .-. ... . -.-. --- -.. . ..-. - .--
```

And use [From Morse Code](https://gchq.github.io/CyberChef/#recipe=From_Morse_Code('Space','Line%20feed')&input=LS0gLS0tIC4tLiAuLi4gLiAtLi0uIC0tLSAtLi4gLiAuLi0uIC0gLi0t) to decode the morse code.
