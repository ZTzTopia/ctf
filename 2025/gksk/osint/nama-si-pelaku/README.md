---
title: Cekidot
categories: OSINT
tags: 
draft: false
completedDuringEvent: true
submitted: true
points: 100
solves: 18
flag: GKSK#9{MorenoSuprapto}
---
> Sebuah file misterius ditemukan dalam repositori proyek internal perusahaan. Tidak ada yang tahu siapa yang menyisipkan pesan rahasia, tetapi ada desas-desus bahwa "namanya bukan sembarang nama." Dapatkah kamu menemukan siapa yang menyisipkan flag ke dalam repositori ini?

by `morenokoprol`

---

Diberikan sebuah file `scriptos-bre.zip`, kita bisa mengekstrak file tersebut. Setelah diekstrak, kita akan mendapatkan sebuah folder baru namu pada folder tersebut terdapat folder `.git`. Karena folder `.git` adalah folder yang menyimpan informasi tentang repository git, kita bisa menggunakan perintah `git log` untuk melihat commit yang ada pada repository tersebut.

```bash
$ git log                                          
commit 0c6f8a1e3167a1aba63adcc35b21fc5b4fbd470d (HEAD -> master)
Author: GKSK#9{MorenoSuprapto} <anonim@gksk#9.com>
Date:   Sun May 25 13:54:39 2025 +0800

    Jangan Dikasi Tau
```
