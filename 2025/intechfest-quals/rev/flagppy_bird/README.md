---
title: "Fla(g)ppy Bird"
categories: "Reverse Engineering"
authors: aimardcr
tags: 
draft: true
completedDuringEvent: true
submitted: true
points: 1000
solves: 1
flags: INTECHFEST{}
hints:
  - Not only the global-metadata.dat is encrypted, but it's header fields (Il2CppGlobalMetadataHeader) is also shuffled, making it impossible for you to recover the original header unless you reverse it for days.
  - There should be a way for you to dump without needing the global-metadata.dat, maybe dynamically?
---

> Flag? Just get 13371337 points!

---

This Unity/IL2CPP Android challenge ships an APK and a custom `libil2cpp.so`. The attacker’s usual route—dumping `global-metadata.dat` and running il2cpp-dumper—has been booby-trapped: the metadata header is "shuffled," and the body is RC4-like encrypted starting at offset 0x108 (decimal 264). Instead of fighting the static metadata, we pivot to *dynamic* IL2CPP APIs with Frida, bypass the library’s image-integrity check, and then abuse the game logic to force the score past a magic threshold (0xCC07C8 = 13371336) by writing a consistent `(score, encryptedScore)` pair. Below is the reverse path, the two bypass methods, and the final scoring hook.

```c
const void *__fastcall sub_2BBE58(
        int a1,
        int a2,
        int a3,
        int a4,
        int a5,
        int a6,
        int a7,
        int a8,
        int a9,
        int a10,
        int a11,
        char a12,
        int a13,
        __int64 a14,
        void *a15,
        __int64 a16,
        __int64 a17)
{
  const void *result; // x0
  size_t v18; // x20
  const void *v19; // x19
  void *v20; // x0
  int v21; // w8
  const char **v22; // x26
  int *v23; // x23
  const char *v24; // x19
  size_t v25; // x0
  size_t v26; // x20
  __int64 v27; // x28
  __int64 v28; // x27
  char *v29; // x21
  char *v30; // x8
  char *v31; // x0
  __int64 v32; // x19
  const char *v33; // x1
  int *v34; // x8
  __int64 v35; // x10
  __int64 v36; // x9
  __int64 v37; // x20
  unsigned int v38; // w21
  const char *v39; // x19
  unsigned __int64 i; // x22
  const char **v41; // x23
  __int64 v42; // x8
  __int64 v43; // x9
  __int64 v44; // x19
  __int64 v45; // x20
  __int64 j; // x21
  __int64 v47; // x11
  __int64 v48; // x0
  __int64 v49; // x10
  __int64 v50; // x19
  __int64 v51; // x21
  __int64 v52; // x23
  unsigned int v53; // w8
  unsigned __int64 k; // x26
  __int64 v55; // x27
  unsigned int v56; // w28
  __int64 v57; // x8
  int v58; // w8
  __int64 v59; // x8
  __int64 v60; // x19
  __int64 v61; // x20
  int *v62; // x9
  signed __int64 v63; // x8
  int dest; // [xsp+0h] [xbp-A0h]
  int v65; // [xsp+8h] [xbp-98h]
  char v66; // [xsp+10h] [xbp-90h]
  int *v67; // [xsp+10h] [xbp-90h]
  __int128 v68; // [xsp+18h] [xbp-88h] BYREF
  void *ptr; // [xsp+28h] [xbp-78h]
  void *v70; // [xsp+30h] [xbp-70h] BYREF
  char *v71; // [xsp+38h] [xbp-68h]
  void *v72; // [xsp+40h] [xbp-60h]
  size_t size; // [xsp+48h] [xbp-58h] BYREF

  size = 0;
  result = (const void *)sub_2BC5C8(
                           (int)"global-metadata.dat",
                           (int)&size,
                           a3,
                           a4,
                           a5,
                           a6,
                           a7,
                           a8,
                           dest,
                           v65,
                           v66,
                           v68,
                           *((void **)&v68 + 1),
                           (char)ptr,
                           (int)v70,
                           v71);
  if ( !result )
    return result;
  v18 = size;
  v19 = result;
  v20 = malloc(size);
  qword_A00A38 = (__int64)v20;
  if ( !v20 )
  {
    sub_309D3C(v19);
    return 0;
  }
  memcpy(v20, v19, v18);
  sub_309D3C(v19);
  sub_2BBD4C(qword_A00A38 + 264, v18 - 264, qword_A00A38, 264, qword_A00A38 + 264, &size);
  sub_301A9C(*(unsigned int *)(qword_A00A30 + 4));
  qword_A00A40 = qword_A00A38;
  qword_A00A48 = sub_309CF8(*(int *)(qword_A00A28 + 48), 8);
  qword_A00A50 = sub_309CF8(*(int *)(qword_A00A40 + 236) / 0x5CuLL, 8);
  qword_A00A58 = sub_309CF8((unsigned __int64)*(int *)(qword_A00A40 + 176) >> 5, 8);
  qword_A00A60 = sub_309CF8(*(int *)(qword_A00A28 + 64), 8);
  dword_A00A68 = *(int *)(qword_A00A40 + 28) / 0x28uLL;
  qword_A00A70 = sub_309CF8(dword_A00A68, 80);
  v21 = *(_DWORD *)(qword_A00A40 + 156);
  dword_A00A78 = v21 >> 6;
  qword_A00A80 = sub_309CF8((__int64)v21 >> 6, 88);
  if ( dword_A00A68 < 1 )
    goto LABEL_37;
  v22 = (const char **)qword_A00A70;
  v23 = (int *)(qword_A00A38 + *(int *)(qword_A00A40 + 64));
  v24 = (const char *)(qword_A00A38 + *(int *)(qword_A00A40 + 92) + *v23);
  *(_QWORD *)qword_A00A70 = v24;
  v68 = 0u;
  ptr = 0;
  v25 = strlen(v24);
  if ( v25 > 0xFFFFFFFFFFFFFFEFLL )
LABEL_30:
    sub_29AB68(&v68);
  v26 = v25;
  v27 = 0;
  v28 = (__int64)v22;
  v67 = v23;
  while ( 1 )
  {
    if ( v26 >= 0x17 )
    {
      v29 = (char *)operator new((v26 + 16) & 0xFFFFFFFFFFFFFFF0LL);
      *((_QWORD *)&v68 + 1) = v26;
      ptr = v29;
      *(_QWORD *)&v68 = (v26 + 16) & 0xFFFFFFFFFFFFFFF0LL | 1;
LABEL_10:
      memcpy(v29, v24, v26);
      goto LABEL_11;
    }
    v29 = (char *)&v68 + 1;
    LOBYTE(v68) = 2 * v26;
    if ( v26 )
      goto LABEL_10;
LABEL_11:
    v29[v26] = 0;
    sub_30A230(&v70, &v68);
    if ( (v68 & 1) != 0 )
      operator delete(ptr);
    if ( ((unsigned __int8)v70 & 1) != 0 )
      v30 = v71;
    else
      v30 = (char *)((unsigned __int64)(unsigned __int8)v70 >> 1);
    v31 = (char *)sub_309CF8(v30 + 1, 1);
    v32 = v28 + 80 * v27;
    *(_QWORD *)(v32 + 8) = v31;
    if ( ((unsigned __int8)v70 & 1) != 0 )
      v33 = (const char *)v72;
    else
      v33 = (char *)&v70 + 1;
    strcpy(v31, v33);
    v34 = &v23[10 * v27];
    v35 = v34[1];
    v36 = qword_A00A80 + 88 * v35;
    if ( (_DWORD)v35 == -1 )
      v36 = 0;
    *(_QWORD *)(v32 + 16) = v36;
    *(_DWORD *)(v32 + 24) = v34[2];
    *(_DWORD *)(v32 + 28) = v34[3];
    *(_DWORD *)(v32 + 32) = v34[4];
    *(_DWORD *)(v32 + 36) = v34[5];
    *(_DWORD *)(v32 + 48) = v34[6];
    *(_DWORD *)(v32 + 72) = v34[7];
    *(_DWORD *)(v32 + 40) = v34[8];
    *(_DWORD *)(v32 + 44) = v34[9];
    v37 = qword_A00A20;
    v38 = *(_DWORD *)(qword_A00A20 + 120);
    if ( v38 )
    {
      v39 = *v22;
      for ( i = 0; i < v38; ++i )
      {
        v41 = *(const char ***)(*(_QWORD *)(v37 + 128) + 8 * i);
        if ( !strcmp(v39, *v41) )
        {
          *(_QWORD *)(v28 + 80 * v27 + 64) = v41;
          v38 = *(_DWORD *)(v37 + 120);
        }
      }
    }
    *(_BYTE *)(v28 + 80 * v27 + 76) = 0;
    if ( ((unsigned __int8)v70 & 1) != 0 )
      operator delete(v72);
    v42 = qword_A00A38;
    v43 = qword_A00A40;
    v23 = v67;
    if ( ++v27 >= dword_A00A68 )
      break;
    v28 = qword_A00A70;
    v24 = (const char *)(qword_A00A38 + *(int *)(qword_A00A40 + 92) + v67[10 * v27]);
    v22 = (const char **)(qword_A00A70 + 80 * v27);
    *v22 = v24;
    v68 = 0u;
    ptr = 0;
    v26 = strlen(v24);
    if ( v26 > 0xFFFFFFFFFFFFFFEFLL )
      goto LABEL_30;
  }
  if ( dword_A00A68 >= 1 )
  {
    v44 = 0;
    v45 = 1;
    for ( j = qword_A00A38 + *(int *)(qword_A00A40 + 8) + 28; ; j += 64 )
    {
      v47 = *(int *)(j - 28);
      v48 = qword_A00A80 + v44;
      v49 = qword_A00A70 + 80 * v47;
      if ( (_DWORD)v47 == -1 )
        v49 = 0;
      *(_QWORD *)v48 = v49;
      *(_DWORD *)(v48 + 8) = *(_DWORD *)(j - 24);
      *(_DWORD *)(v48 + 12) = *(_DWORD *)(j - 20);
      *(_DWORD *)(v48 + 16) = *(_DWORD *)(j - 16);
      *(_QWORD *)(v48 + 24) = v42 + *(int *)(v43 + 92) + *(int *)(j - 12);
      *(_QWORD *)(v48 + 32) = v42 + *(int *)(v43 + 92) + *(int *)(j - 8);
      *(_QWORD *)(v48 + 40) = v42 + *(int *)(v43 + 92) + *(int *)(j - 4);
      *(_DWORD *)(v48 + 48) = *(_DWORD *)j;
      *(_DWORD *)(v48 + 52) = *(_DWORD *)(j + 4);
      *(_DWORD *)(v48 + 56) = *(_DWORD *)(j + 8);
      *(_DWORD *)(v48 + 60) = *(_DWORD *)(j + 12);
      *(_DWORD *)(v48 + 64) = *(_DWORD *)(j + 16);
      *(_DWORD *)(v48 + 68) = *(_DWORD *)(j + 20);
      *(_DWORD *)(v48 + 72) = *(_DWORD *)(j + 24);
      *(_QWORD *)(v48 + 76) = *(_QWORD *)(j + 28);
      sub_2AF518();
      if ( v45 >= dword_A00A68 )
        break;
      v42 = qword_A00A38;
      v43 = qword_A00A40;
      v44 += 88;
      ++v45;
    }
  }
LABEL_37:
  sub_2BC7A4();
  v71 = 0;
  v72 = 0;
  v70 = 0;
  if ( dword_A00A78 >= 1 )
  {
    v50 = 0;
    v51 = qword_A00A38 + *(int *)(qword_A00A40 + 56);
    do
    {
      v52 = *(_QWORD *)(qword_A00A80 + 88 * v50);
      v53 = *(_DWORD *)(v52 + 28);
      if ( v53 )
      {
        for ( k = 0; k < v53; ++k )
        {
          v55 = v51 + 92LL * *(int *)(v52 + 24) + 92 * k;
          if ( *(_WORD *)(v55 + 68) )
          {
            v56 = 0;
            do
            {
              v57 = *(int *)(qword_A00A40 + 116);
              DWORD2(v68) = v56 + *(_DWORD *)(v55 + 40);
              v58 = *(_DWORD *)(qword_A00A38 + v57 + 32LL * SDWORD2(v68) + 20) & 0xFFFFFF;
              if ( v58 )
              {
                *(_QWORD *)&v68 = *(_QWORD *)(*(_QWORD *)(*(_QWORD *)(v52 + 64) + 16LL) + 8LL * (unsigned int)(v58 - 1));
                if ( (_QWORD)v68 )
                {
                  if ( v71 == v72 )
                  {
                    sub_2DFBA4(&v70, &v68);
                  }
                  else
                  {
                    *(_OWORD *)v71 = v68;
                    v71 += 16;
                  }
                }
              }
              else
              {
                *(_QWORD *)&v68 = 0;
              }
              ++v56;
            }
            while ( v56 < *(unsigned __int16 *)(v55 + 68) );
            v53 = *(_DWORD *)(v52 + 28);
          }
        }
      }
      ++v50;
    }
    while ( v50 < dword_A00A78 );
  }
  v59 = qword_A00A28;
  if ( *(int *)(qword_A00A28 + 32) >= 1 )
  {
    v60 = 0;
    v61 = 0;
    do
    {
      v62 = (int *)(*(_QWORD *)(v59 + 40) + v60);
      DWORD2(v68) = *(_DWORD *)(*(_QWORD *)(v59 + 72) + 12LL * *v62);
      *(_QWORD *)&v68 = *(_QWORD *)(*(_QWORD *)(qword_A00A20 + 24) + 8LL * v62[1]);
      if ( v71 == v72 )
      {
        sub_2DFBA4(&v70, &v68);
        v59 = qword_A00A28;
      }
      else
      {
        *(_OWORD *)v71 = v68;
        v71 += 16;
      }
      ++v61;
      v60 += 16;
    }
    while ( v61 < *(int *)(v59 + 32) );
  }
  sub_313E6C(&v70);
  if ( v70 )
  {
    v63 = (_BYTE *)v70 - v71 - 16;
    do
      v63 += 16LL;
    while ( v63 );
    v71 = (char *)v70;
    operator delete(v70);
  }
  return &dword_0 + 1;
}
```

`sub_2BBE58` reads `global-metadata.dat` into heap (`qword_A00A38`), then calls `sub_2BBD4C` to decrypt **everything after the first 264 bytes**.

```c
char *__fastcall sub_2BBD4C(char *result, __int64 a2, __int64 a3, unsigned __int64 a4, _BYTE *a5, _QWORD *a6)
{
  int8x16_t v6; // q0
  __int64 v7; // x8
  int8x16_t v8; // q1
  unsigned __int64 v9; // x8
  unsigned int v10; // w10
  int v11; // w11
  int v12; // w10
  int v13; // w12
  unsigned int v14; // w10
  int v15; // w8
  int v16; // w11
  int v17; // w8
  int v18; // w11
  int v19; // w10
  int v20; // w12
  char v21; // t1
  _BYTE v22[256]; // [xsp+0h] [xbp-110h]

  if ( a6 )
    *a6 = a2;
  v6 = (int8x16_t)xmmword_7CA7C0;
  v7 = 0;
  v8.n128_u64[0] = 0x1010101010101010LL;
  v8.n128_u64[1] = 0x1010101010101010LL;
  do
  {
    *(int8x16_t *)&v22[v7] = v6;
    v7 += 16;
    v6 = vaddq_s8(v6, v8);
  }
  while ( v7 != 256 );
  v9 = 0;
  v10 = 0;
  do
  {
    v11 = (unsigned __int8)v22[v9];
    v12 = v10 + v11 + *(unsigned __int8 *)(a3 + v9 % a4);
    v13 = v12 + 255;
    if ( v12 >= 0 )
      v13 = v12;
    v10 = v12 - (v13 & 0xFFFFFF00);
    v22[v9++] = v22[v10];
    v22[v10] = v11;
  }
  while ( v9 != 256 );
  if ( a2 )
  {
    v14 = 0;
    v15 = 0;
    do
    {
      v16 = v15 + 1;
      if ( v15 + 1 >= 0 )
        v17 = v15 + 1;
      else
        v17 = v15 + 256;
      v15 = v16 - (v17 & 0xFFFFFF00);
      v18 = (unsigned __int8)v22[v15];
      v19 = v14 + v18;
      v20 = v19 + 255;
      if ( v19 >= 0 )
        v20 = v19;
      v14 = v19 - (v20 & 0xFFFFFF00);
      --a2;
      v22[v15] = v22[v14];
      v22[v14] = v18;
      v21 = *result++;
      *a5++ = v22[(unsigned __int8)(v22[v15] + v18)] ^ v21;
    }
    while ( a2 );
  }
  return result;
}
```

This is effectively **RC4**. The KSA fills an S-box (`v22[256]`) using a key that cycles through `a4` bytes starting at `a3` (i.e., the first 264 bytes of the file). The PRGA then XOR-decrypts `a2` bytes from `result` into `a5`. In `sub_2BBE58`, `result` and `a5` point to the same body (`qword_A00A38 + 264`), so the decrypt happens **in place**. Takeaway: header stays shuffled; body becomes readable to *this* process only.

## Method 1 — Don't call the booby-trapped API

```c
__int64 __fastcall il2cpp_assembly_get_image(__int64 a1)
{
  unsigned __int64 v1; // x30
  __int64 v3; // x0
  _QWORD v5[2]; // [xsp+0h] [xbp-20h] BYREF
  char v6; // [xsp+1Ch] [xbp-4h] BYREF

  if ( qword_9FFEA0 - 1 < v1 && qword_9FFEA8 >= v1 )
    return sub_2AF330(a1);
  if ( qword_9FFEB0 - 1 < v1 && qword_9FFEB8 >= v1 )
    return sub_2AF330(a1);
  v6 = 0;
  v5[0] = v1;
  v5[1] = &v6;
  v3 = dl_iterate_phdr((int (*)(struct dl_phdr_info *, size_t, void *))sub_293698, v5);
  if ( v6 )
    return sub_2AF330(a1);
  else
    return sub_292148(v3);
}
```

`il2cpp_assembly_get_image` acts as an **anti-hook/anti-introspection gate**. It captures the LR (return address) and checks whether the caller lives inside one of two hard-coded address ranges; otherwise it walks ELF program headers via `dl_iterate_phdr` to decide if the caller belongs to an "approved" module. If not, it refuses to return the true `Il2CppImage*` and instead calls:

```c
_BYTE *sub_292148()
{
  unsigned int v0; // w0
  __int64 i; // x19
  _BYTE v3[32]; // [xsp+0h] [xbp-30h] BYREF

  v0 = time(0);
  srand(v0);
  for ( i = 0; i != 32; ++i )
    v3[i] = rand();
  return v3;
}
```

So untrusted callers get **junk** instead of the image pointer.

```ts
import Java from "frida-java-bridge";

const PTR_SIZE = Process.pointerSize;
const SIZE_T = PTR_SIZE === 8 ? "ulong" : "uint";
const MASK64 = ptr("0x00ffffffffffffff"); // strip top-byte tag (AArch64 TBI/MTE)

const untag = (p: NativePointer) =>
  (Process.arch === "arm64") ? p.and(MASK64) : p;

function tryReadUtf8String(p: NativePointer): string | null {
  if (p.isNull()) {
    return "";
  }

  try {
    return p.readUtf8String();
  } catch {
    return "";
  }
}

function looksPrintableId(s: string) {
  // tolerate C# identifiers + dots/backticks for generics
  return s.length > 0 && s.length < 256 && /^[\w.`$<>+,-]+$/.test(s);
}

// Fast fallback if export fails: scan MethodInfo head for a likely name ptr
function readMethodNameViaStruct(mi: NativePointer): string {
  const base = untag(mi);
  // scan first 0x80 bytes for a pointer to a short printable string
  for (let off = 0; off < 0x80; off += PTR_SIZE) {
    const p = base.add(off).readPointer();
    const s = tryReadUtf8String(p) || "";
    if (looksPrintableId(s) && /[A-Za-z_]/.test(s[0])) {
      return s;
    }
  }

  return "";
}

Java.perform(() => {
  console.log("[*] Java:", Java.available);

  setTimeout(() => {
    Java.enumerateLoadedClasses({
      onMatch: (className) => {},
      onComplete: () => {
        const m = Process.getModuleByName("libil2cpp.so");

        console.log("[*] libil2cpp.so base address:", m.base);

        const il2cpp_thread_attach = new NativeFunction(
          m.findExportByName("il2cpp_thread_attach")!,
          "pointer",
          ["pointer"]
        );

        const il2cpp_domain_get = new NativeFunction(
          m.findExportByName("il2cpp_domain_get")!,
          "pointer",
          []
        );

        const il2cpp_domain_get_assemblies = new NativeFunction(
          m.findExportByName("il2cpp_domain_get_assemblies")!,
          "pointer",
          ["pointer", "pointer"]
        );

        const il2cpp_assembly_get_image = new NativeFunction(
          m.findExportByName("il2cpp_assembly_get_image")!,
          "pointer",
          ["pointer"]
        );

        const il2cpp_image_get_name = new NativeFunction(
          m.findExportByName("il2cpp_image_get_name")!,
          "pointer",
          ["pointer"]
        );

        const il2cpp_image_get_class_count = new NativeFunction(
          m.findExportByName("il2cpp_image_get_class_count")!,
          SIZE_T,
          ["pointer"]
        );

        const il2cpp_image_get_class = new NativeFunction(
          m.findExportByName("il2cpp_image_get_class")!,
          "pointer",
          ["pointer", SIZE_T]
        );

        const il2cpp_class_get_type = new NativeFunction(
          m.findExportByName("il2cpp_class_get_type")!,
          "pointer",
          ["pointer"]
        );

        const il2cpp_type_get_name = new NativeFunction(
          m.findExportByName("il2cpp_type_get_name")!,
          "pointer",
          ["pointer"]
        );

        const il2cpp_class_get_methods = new NativeFunction(
          m.findExportByName("il2cpp_class_get_methods")!, "pointer", ["pointer", "pointer"]
        );
        const il2cpp_method_get_name = new NativeFunction(
          m.findExportByName("il2cpp_method_get_name")!, "pointer", ["pointer"]
        );
        const il2cpp_method_get_param_count = new NativeFunction(
          m.findExportByName("il2cpp_method_get_param_count")!, "uint", ["pointer"]
        );

        setTimeout(() => {
          try {
            const domain = il2cpp_domain_get();
            if (!domain) {
              return console.error("[!] il2cpp_domain_get() returned null");
            }

            console.log("[*] il2cpp_domain_get():", domain);
            il2cpp_thread_attach(domain);

            const assembliesSizePtr = Memory.alloc(PTR_SIZE);
            assembliesSizePtr.writeU64(0);
            const assembliesPtr = il2cpp_domain_get_assemblies(domain, assembliesSizePtr);
            const assembliesCount = Number(assembliesSizePtr.readU64());

            console.log(`[*] ${assembliesCount} assemblies loaded`);

            for (let i = 0; i < assembliesCount; i++) {
              const assembly = assembliesPtr.add(i * PTR_SIZE).readPointer();
              console.log(`    [*] Assembly ${i}:`, assembly);

              /* const image = il2cpp_assembly_get_image(assembly);
              console.log(`         image:`, image);

              const namePtr = il2cpp_image_get_name(image);
              console.log(`         namePtr:`, namePtr);

              const name = namePtr.isNull() ? "" : namePtr.readByteArray(32);
              console.log(`         name:`, name); */

              const image = untag(assembly).readPointer();

              const pName = untag(image).readPointer();
              const pNameNoExt = untag(image).add(PTR_SIZE).readPointer();
              const pAsmName = untag(image).add(2 * PTR_SIZE).readPointer();

              const name = tryReadUtf8String(pName);
              const nameNoExt = tryReadUtf8String(pNameNoExt);
              const asmName = tryReadUtf8String(pAsmName);

              console.log(
                `    [*] Assembly ${i}: ${assembly}\n` +
                `         image: ${image}\n` +
                `         name: ${name}\n` +
                `         nameNoExt: ${nameNoExt}\n` +
                `         assemblyName: ${asmName}`
              );

              if (name !== "Assembly-CSharp.dll") {
                continue;
              }

              const classCount = il2cpp_image_get_class_count(image);
              console.log(`         classCount:`, classCount);

              for (let j = 0; j < classCount; j++) {
                const klass = il2cpp_image_get_class(image, j);

                const pName = untag(klass).add(2 * PTR_SIZE).readPointer();

                const name = tryReadUtf8String(pName);

                console.log(`             [*] Class ${j}: ${klass} - ${name}`);

                // if (name !== "GameManager") {
                //   continue;
                // }

                const iterPtr = Memory.alloc(PTR_SIZE);
                iterPtr.writePointer(NULL);

                while (true) {
                  const methodsPtr = il2cpp_class_get_methods(untag(klass), iterPtr);
                  if (methodsPtr.isNull()) {
                    break;
                  }

                  const methodNamePtr = il2cpp_method_get_name(untag(methodsPtr));
                  const methodName = tryReadUtf8String(methodNamePtr);
                  const methodNameViaStruct = readMethodNameViaStruct(methodsPtr);

                  const paramCount = il2cpp_method_get_param_count(untag(methodsPtr));
                  const VA = untag(methodsPtr).readPointer();
                  const RVA = VA.sub(untag(m.base));

                  console.log(`                 - Method: ${VA} (RVA ${untag(RVA)}) ${methodNameViaStruct} (params: ${paramCount})`);
                }
              }
            }
          } catch (e) {
            return console.error("[!] Failed:", e);
          }
        }, 1500);
      }
    });
  }, 1000);
});
```

Instead of ever calling the guarded `il2cpp_assembly_get_image`, we **walk the Il2CppAssembly and Il2CppImage layouts directly** in memory. On this binary, the first pointer in `Il2CppAssembly` is the image pointer, and the first three pointers of `Il2CppImage` are name strings. Because this is ARM64 with Top-Byte-Ignore/MTE tagging, we mask addresses with `0x00ffffffffffffff` via `untag()` before dereferencing. We then enumerate classes/methods using other IL2CPP exports, or even by fishing strings from the structs when helper exports are inconvenient.

## Method 2 — Make the booby-trap bless us

```c
__int64 __fastcall il2cpp_assembly_get_image(__int64 a1)
```

Same guard as above. The **shortcut** is to hook `dl_iterate_phdr` and force the "seen" byte to 1 so the call always returns the real image.

```ts
import "frida-il2cpp-bridge";
import Java from "frida-java-bridge";

Interceptor.attach(Module.getGlobalExportByName("dl_iterate_phdr"), {
    onEnter(args) {
        this.cb = args[0];
        this.data = args[1];

        try {
            const seenPtr = this.data.add(Process.pointerSize).readPointer();
            // console.log('[*] seenPtr =', seenPtr);
            if (!seenPtr.isNull()) {
                seenPtr.writeU8(1);
                // console.log('[*] forced seen=1');
            }
        } catch (e) {
            console.error(e);
        }
    },
    onLeave(retval) {}
});

Java.perform(() => {
  console.log("[*] Java:", Java.available);

  setTimeout(() => {
    Java.enumerateLoadedClasses({
      onMatch: (className) => {},
      onComplete: () => {
        Il2Cpp.perform(() => {
            console.log(`Hello, Unity ${Il2Cpp.unityVersion}`);

            Il2Cpp.domain.assembly("Assembly-CSharp").image.classes.forEach(klass => {
                console.log(`[*] ${klass.name} (${klass.methods.length} methods)`);
                klass.methods.forEach(method => {
                    console.log(`   [*] ${method.name} (${method.parameters.length} params) (VA: ${method.virtualAddress}) (RVA: ${method.relativeVirtualAddress})`);
                });
            });
        });
      }
    });
  }, 1000);
});
```

We hook the glibc enumerator, nudge the callback’s `seen` output, and then it’s safe to use the ergonomic `frida-il2cpp-bridge` wrappers because `il2cpp_assembly_get_image` now cooperates.

## Getting 13371337 points

With either method we get a clean list, trimmed highlights:

```
CryptoUtils
  EncryptInt        RVA 0x6d44f4
  DecryptInt        RVA 0x6d45d4
  ...
GameManager
  get_score         RVA 0x6d501c   // LDR W0, [X0,#0x44]
  set_score         RVA 0x6d5024
  get_encryptedScore RVA 0x6d502c  // LDR W0, [X0,#0x48]
  set_encryptedScore RVA 0x6d5034
  IncreaseScore     RVA 0x6d5460
```

The `GameManager` has a score property at offset `0x44` and an "encryptedScore" at `0x48`. The `IncreaseScore` method (RVA `0x6D5460`) is the only place that writes to these fields, so let’s look at it in detail.

```c
// Layout guesses from field offsets used here
struct Obj {
    uint8_t  flag40;      // +0x40
    uint32_t counter44;   // +0x44
    uint32_t state48;     // +0x48
    void*    listener28;  // +0x28 (vtbl at [listener][0])
};

// Globals / singletons
static uint8_t  g_once_flag_9FFAF3;                 // byte_9FFAF3
static uint32_t *g_init_param_dword_710F00;         // via off_9956A8
static void    **g_alloc_ctx_qword_A0B1C8;          // via off_99AAE8
static void    **g_source_ctx_qword_A10A50;         // via off_9A4FA8

// vtbl slots (offsets seen):
// listener vtbl: +0x5E0 (fn), +0x5E8 (arg2)
// service  vtbl: +0x320 (fn), +0x328 (arg2)

void sub_6D5460(struct Obj *self)
{
    // one-time init
    if ((g_once_flag_9FFAF3 & 1) == 0) {
        sub_3151A8(*g_init_param_dword_710F00);
        g_once_flag_9FFAF3 = 1;
    }

    // bump counter and emit a formatted thingy (sub_492394)
    uint32_t cnt = self->counter44 + 1;
    self->counter44 = cnt;

    uint32_t tmp_on_stack = cnt;
    // signature looks like sub_492394(&tmp, 0)
    void *fmt = sub_492394(&tmp_on_stack, /*x1*/0);

    // If listener present, call listener->fn(this, fmt, listener->arg2)
    if (self->listener28) {
        void **vtbl = *(void***)self->listener28;
        void *fn    = *(void **)((uint8_t*)vtbl + 0x5E0);
        void *arg2  = *(void **)((uint8_t*)vtbl + 0x5E8);
        // BLR X9 with: X0=this->listener28, X1=fmt, X2=arg2
        ((void (*)(void*,void*,void*))fn)(self->listener28, fmt, arg2);
    }

    // normalize / advance state vs threshold
    const uint32_t THRESH = 0xCC07C8;  // W21
    uint32_t cur = self->state48;
    uint32_t norm = sub_6D45D4(cur);

    if (norm <= THRESH) {
        // step state via table map then re-normalize
        self->state48 = sub_6D44F4(norm + 1);
        norm = sub_6D45D4(self->state48);
    }

    // flag if counter != current normalized value
    if (self->counter44 != norm)
        self->flag40 = 1;

    // Below runs only after norm > THRESH
    if (norm > THRESH) {
        // allocate ~0x40 bytes from ctx, then bind to a source
        void *alloc_ctx = *g_alloc_ctx_qword_A0B1C8;
        void *blob = sub_3151B8(alloc_ctx, /*size*/0x40);

        void *source_ctx = *g_source_ctx_qword_A10A50;
        blob = sub_536844(blob, source_ctx, /*x2*/0);

        if (!blob) goto cleanup;

        // blob layout: [0x18]=length (W), [0x20..]=data
        uint32_t len = *(uint32_t *)((uint8_t*)blob + 0x18);
        if (len >= 1) {
            uint8_t *p = (uint8_t*)blob + 0x20;
            for (uint32_t i = 0; i < len; i++)
                p[i] ^= 0xA0;  // XOR decode
        }

        // get a service/singleton and submit blob
        void *svc = sub_574830(0);
        if (!svc) goto cleanup;

        void **svtbl = *(void***)svc;
        void *svc_fn = *(void **)((uint8_t*)svtbl + 0x320);
        void *svc_a2 = *(void **)((uint8_t*)svtbl + 0x328);
        // returns a handle H:
        void *H = ((void *(*)(void*,void*,void*))svc_fn)(svc, blob, svc_a2);

        // ---- compute size/selector and CALL sub_6D4CBC ----
        // W1 = 0x100; X0 = sub_6D45D4(self->state48)
        uint32_t sel = sub_6D45D4(self->state48);
        void *sz = sub_6D4EC8(sel, /*0x100*/ 0x100);

        // X0=H, X1=sz
        void *result = sub_6D4CBC(H, sz);

        // If listener exists: listener->fn(listener, result, listener->arg2)
        if (self->listener28) {
            void **lvt = *(void***)self->listener28;
            void *lfn  = *(void **)((uint8_t*)lvt + 0x5E0);
            void *la2  = *(void **)((uint8_t*)lvt + 0x5E8);
            ((void (*)(void*,void*,void*))lfn)(self->listener28, result, la2);
        }
    }

cleanup:
    // both early-outs funnel here
    sub_315270(); // likely leave/cleanup/log
}
```

The decompiled `IncreaseScore` shows a normalized state (via `sub_6D45D4`) compared to a threshold:

- `THRESH = 0xCC07C8` (13371336).
- If `sub_6D45D4(state48)` ≤ THRESH, the function advances the state using `sub_6D45D4(norm + 1)` and loops naturally.
- Once `norm > THRESH`, it decodes a small blob (XOR 0xA0), calls into a service, and ultimately lands in the “reward” branch (flag path).
- There’s also a mismatch guard: if `counter44 != norm`, it sets `flag40` and you don’t get the prize.

So, we simply **write a coherent pair**:

- `score = 13371337`
- `encryptedScore = sub_6D45D4(13371337)`

and let a single `IncreaseScore` tick do the rest.

```ts
import Java from "frida-java-bridge";

Java.perform(() => {
    console.log("Java:", Java.available);

    setTimeout(() => {
        Java.enumerateLoadedClasses({
            onMatch: (className) => { },
            onComplete: () => {
                const m = Process.getModuleByName('libil2cpp.so');

                console.log("[*] libil2cpp.so base address:", m.base);

                const SCORE = 13371337;

                const fnPtr = m.base.add(0x6d5024); // set_score
                const fn = new NativeFunction(fnPtr, 'void', ['pointer', 'int']);

                const fn2Ptr = m.base.add(0x6d5034); // set_encryptedScore
                const fn2 = new NativeFunction(fn2Ptr, 'void', ['pointer', 'int']);

                const fn3Ptr = m.base.add(0x6D44F4); // Encrypt?
                const fn3 = new NativeFunction(fn3Ptr, 'int', ['int']);

                Interceptor.attach(m.base.add(0x6d5460), {
                    onEnter(args) {
                        console.log('IncreaseScore called');

                        fn(args[0], SCORE);

                        console.log(`Calling set_encryptedScore with ${fn3(SCORE)}`);
                        fn2(args[0], Number(fn3(SCORE)));
                    },
                    onLeave(retval) { }
                });
            }
        });
    }, 1000);
});
```

We resolve RVAs against `libil2cpp.so` base and build three `NativeFunction`s: the two setters and `sub_6D45D4`. We hook `IncreaseScore` so the game’s own loop calls us at the right time with a valid `this` pointer. Inside `onEnter`, we *first* write the clear score for UI happiness and *then* compute the matching ciphertext by calling the game’s own `sub_6D45D4`. Keeping `(score, encryptedScore)` **consistent** is crucial; otherwise later checks flip a "mismatch" flag at `+0x40` and avoid the prize branch.
