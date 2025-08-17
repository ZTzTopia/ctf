---
title: "MISSING 00"
categories: OSINT
tags: 
draft: false
completedDuringEvent: true
submitted: true
points: 100
solves: 16
flag: GKSK#9{enjoy_the_game_guys!}
---
> Dr. **Eris Nugroho**, seorang pakar IT, kriptografi, dan sistem terdistribusi global, menghilang tanpa jejak tepat satu hari setelah menyampaikan bahwa ia “nyaris menemukan sesuatu yang seharusnya tak boleh ditemukan.”
>
> Dalam minggu-minggu terakhir sebelum menghilang, Eris menunjukkan tanda-tanda paranoia:
>
> - Kamera laptopnya dilakban permanen
> - Semua komunikasi disandikan dan dibungkam
> - Coretan kode acak muncul di buku catatan fisiknya
> - Satu simbol: `∴303`—berulang kali tertulis di sudut halaman
>
> Sehari sebelum ia lenyap, sebuah anomali terjadi—Eris mengunggah sebuah gambar aneh ke server pribadi yang hampir tidak pernah ia akses. File > tersebut dikirim hanya kepada beberapa orang terpilih, dengan subjek email yang hanya berbunyi:
>
> > Bagi yang melihat, jangan hanya menatap. Dalami isinya.
> ---
> Banyak yang menduga ini adalah pesan terakhir… atau mungkin sebuah undangan tersembunyi.
>
> Di balik pesan-pesan terenkripsi, satu nama terus muncul:
> 
> # RoTscura 13
> Entitas misterius.
> Tidak memiliki situs resmi.
> Tidak meninggalkan jejak.
> Hanya simbol. Hanya sisa-sisa metadata.
> Namun selalu ada di ambang… seolah mengamati dari pinggir dunia digital.
>
> Dalam komunitas terbatas mereka, Eris dikenal sebagai **“Architect 7H**”, satu dari sedikit yang diduga pernah **berinteraksi langsung** dengan lapisan terdalam pesan RoTscura.
>
> Kini, Anda—dan hanya segelintir lainnya—telah menerima akses ke fragmen-fragmen yang ditinggalkannya.
>
> Namun **waspadalah**. Mereka yang menggali terlalu dalam ke dalam teka-teki RoTscura 13...
>
> > …tidak selalu kembali dengan jawaban.
> > …dan terkadang, tidak kembali sama sekali.

by `VorpalSoul`

---

Diberikan sebuah file bernama `00.jpg`, yang ternyata adalah sebuah file gambar yang berisi data tersembunyi. Kita dapat menggunakan `strings` untuk melihat printable string yang ada di dalamnya:

```bash
/XPj
D@)l
(]f*
4@Dl@h
xiDS
?r-/
GYv0
X2rh|c
GKSK#9{enjoy_the_game_guys!}
```
