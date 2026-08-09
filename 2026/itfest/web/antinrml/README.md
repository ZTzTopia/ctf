---
title: antinrml
categories: "Web Exploitation"
tags: 
draft: false
points: 104
solves: 23
flags: ITFEST26{7h4nK_Y0U_A_buylN6_mE_sOM3_6EA72_23ab3e467979}
---

> ANTINRML adalah pasar beat hipdut bawah tanah — tempat producer ketemu pembeli. Sekilas tampilannya kayak toko online biasa: ada login, katalog beat, keranjang, riwayat pembelian, dan profil. Kelihatan seperti aplikasi CRUD e-commerce standar.
>
> Kamu bantuin seorang rapper upcoming dari Citayem yang lagi seret duit. Dia pengen banget si SECRET BEATS — ANTINRML Exclusive, tapi harganya jauh di atas saldo yang dia punya.
>
> Di suatu tempat di dalam sistem ini, master dari beat eksklusif itu disimpan. Ambil.
>
> Daftar akun sendiri untuk memulai
>
> Author: UTARA

---

A regular website, we can add items to our cart, purchase items, and view our purchase history.

![alt text](file-858e87cba3dcbd6d3c0885b4bbd9e48d.png)

Tried buying the item with a minus amount, and it worked, and the purchase was successful. However, the item didn't appear in our purchase history.

![alt text](image.png)

However, the money in our account would increase, and we could buy other items that cost more than our initial balance.

![alt text](image-1.png)

Tried buying the two most expensive items.

![alt text](image-2.png)

Just look at our purchase history, and we'll get the flag.

![alt text](image-3.png)
