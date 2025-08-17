---
title: Komentar
categories: OSINT
tags: 
draft: false
completedDuringEvent: true
submitted: true
points: 100
solves: 17
flags: flag: GKSK#9{You_Found_My_Comment}
---
> Ok Ok. Bentar, ini apaan? Eh ini temanku ngirim foto, tapi aku gatau ini tuh foto konser kah atau foto apaan… Coba Kalian cari ini tuh konser atau apa (kayaknya sih konser live di salah satu platform streaming atau video). Nah, Di salah satu video konser tuh ada komen, nah coba check in aja dah. Makasih!
>
> `GKSK#9{Komentar_ada_di_video_konser}`

by `162xf`

---

Diberikan file `apaya.png` yang berisi screenshot dari sebuah video, kita bisa melakukan reverse image search menggunakan Google Lens. Kita akan menemukan sebuah [tweet](https://x.com/hololive_En/status/1885616863889260762) yang berisi tentang sebuah konser.

![alt text](image.png)

Kita coba coba mencari beberapa keyword seperti "hololive" dan "Hoshimachi Suisei SuperNova" di YouTube, dan kita akan menemukan sebuah video dengan judul [【チラ見せ】Hoshimachi Suisei 日本武道館 Live "SuperNova"](https://www.youtube.com/watch?v=_o_mtN68KEg). Dari komentar di video tersebut, kita bisa menemukan komentar yang berisi flag yang diminta.

![alt text](image-1.png)
