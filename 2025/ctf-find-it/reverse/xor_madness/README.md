---
title: xor_madness
categories: Reverse Engineering
tags: 
draft: false
completedDuringEvent: true
submitted: true
flags: flag: FindITCTF{iy4_b3n3r_1n1_fl4g_ny4_b4ng}
---
> Bombombini Gusini adalah seorang mahasiswa tahun pertama jurusan Teknologi Informasi yang tengah mendalami cryptography dan malware analysis di mata kuliah Peretasan Beretika. Suatu hari, dosen memberikan tugas berupa sebuah binary file bernama xor_madness.bin. Katanya jika ia berhasil mendapatkan "sesuatu" dari binary file tersebut, maka ia akan langsung mendapatkan nilai A. Bantulah ia untuk bisa mendapatkan "sesuatu" tersebut.

by `mojitodev`

---

A file named `xor_madness.bin` was provided. Upon opening it, it appeared to contain only random characters. Given the name “xor_madness,” I suspected XOR encryption and decided to attempt brute forcing using CyberChef: https://gchq.github.io/CyberChef/#recipe=XOR_Brute_Force(1,100,0,'Standard',false,true,false,'')&input=VXp9d1pHUEdVaHpqJ0xxIH0gYUwifSJMdX8ndEx9aidMcSd9dG4. 

Sure enough, the flag was revealed using key `13`.
