---
title: Cekidot
categories: OSINT
tags: 
draft: false
completedDuringEvent: true
submitted: true
points: 100
solves: 18
flags: GKSK#9{K4dankM4luK4dankNg4duk}
---
> Seorang pembuat batubata membuat flag pada file, namun untungnya sudah dihapus

by `morenokoprol`

---

Diberikan sebuah file `Cekidot.zip`, kita bisa mengekstrak file tersebut. Setelah diekstrak, kita akan mendapatkan sebuah folder baru namu pada folder tersebut terdapat folder `.git`. Karena folder `.git` adalah folder yang menyimpan informasi tentang repository git, kita bisa menggunakan perintah `git log` untuk melihat commit yang ada pada repository tersebut.

```bash
$ git log                                       
commit 04adb2746bb8b7d7f5ec7c59a759c8859aae0ba0 (HEAD -> master)
Author: KoplarKoprol <putu.moreno298@gmail.com>
Date:   Sun May 25 16:27:40 2025 +0800

    menghapus data sensitif

commit 4e89534ae063046d1cba12619742a9ee63947058
Author: KoplarKoprol <putu.moreno298@gmail.com>
Date:   Sun May 25 16:27:01 2025 +0800

    Membuat flag
```

Karena ada commit dengan pesan "menghapus data sensitif", kita bisa menggunakan perintah `git show` untuk melihat isi dari commit tersebut.

```bash
$ git show 04adb2746bb8b7d7f5ec7c59a759c8859aae0ba0
commit 04adb2746bb8b7d7f5ec7c59a759c8859aae0ba0 (HEAD -> master)
Author: KoplarKoprol <putu.moreno298@gmail.com>
Date:   Sun May 25 16:27:40 2025 +0800

    menghapus data sensitif

diff --git a/batubata.txt b/batubata.txt
index ce11aa1..3c9cd19 100644
--- a/batubata.txt
+++ b/batubata.txt
@@ -1 +1 @@
-GKSK#9{K4dankM4luK4dankNg4duk}
+oopsie
```
