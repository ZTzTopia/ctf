---
title: "What am I Hearing"
category: Miscellaneous
tags: 
draft: false
completedDuringEvent: true
submitted: true
flag: CIT{zG48r2FBR6Wn}
---
> Bro what am I hearing rn
>
> Flag Format: CIT{example_flag}

---

Given `flag.wav` file, when we play it, we hear some beeping sounds. The beeps are in a pattern that resembles Morse code. We can decode the Morse code using an online Morse code decoder. We can use [MorseCodeMagic](https://morsecodemagic.com/morse-code-audio-decoder/) to decode the audio file.

After decoding the audio, we will get some random strings. 

```
....................!?.?...?.......?...............?....................?.?.?.?.!!?!.?.?.?!!!!!!!.............!.......................!..?..............................................!.!!!.?.!!!!!!!!!!!!!!!!!!!!!!!!!!!.!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!.........!..?!!!!!!!!!!!!!!!!!.?.!!!!!!!!!!!!!.........................................!.!!!!!!!!!.................................!.?.................................................!..?..........!..?!!!!!!!!!...............................!.
```

We can use [dCode Cipher Identifier](https://www.dcode.fr/cipher-identifier) to identify the cipher used. The cipher identifier will give us a list of possible ciphers. The highest probability cipher is the `Ook!`. But the `Ook!` cipher is always start with `Ook` and end with `!`, `?` or `.`. So we can add `Ook` of each `!` and `?` and `.` character.

Which will give us the following string:

```
Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook!Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook!Ook!Ook.Ook!Ook.Ook.Ook.Ook.Ook.Ook.Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook!Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook!Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook!Ook.Ook!Ook!Ook!Ook.Ook.Ook.Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook.Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook!Ook.Ook.Ook.Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook.Ook.Ook.Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook!Ook.Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook!Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook!Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook!Ook.Ook.Ook.Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook!Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook.Ook!Ook.
```

Executing the `Ook!` cipher in [dCode Ook!](https://www.dcode.fr/ook-language) will give us the flag.
