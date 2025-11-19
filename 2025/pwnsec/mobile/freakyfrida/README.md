---
title: FreakyFrida
categories: Mobile
authors: TK
tags: 
draft: false
completedDuringEvent: true
submitted: true
points: 450
solves: 10
flags: flag{Sup3r_$3cR3T_M0nK3y_FR3aKY_Fl@G_W17h_b@n@n@s_4ll_0v3r_7h3_P14n37}
---

> It started as just another night at the lab. You opened Android Studio, loaded an APK, and whispered those famous words: “Let’s hook something simple…” Frida purred in the terminal. Everything seemed fine — until it wasn’t. Your screen flickered. Logcat went wild. The app whispered back. “Nice try, human.” Suddenly, "console.log(flag)" returned nothing. MainActivity crashed like your hopes of passing OSCP on the first try. You tried again, but the app laughed — a distorted sound echoing through JNI hell. "You think you can control me?" it taunted. Frida was no longer your tool; it had become the master. The app morphed, adapting to your every move. To retrieve the flag, you must outsmart the app's new defenses. Can you break free from Frida's grip and reclaim control? Note: they told me to use a Frida version lower than 17, and I totally agree with that advice, you should too.

---

Given the mobile application, our initial approach to retrieve the flag involved using Frida to hook into the native function responsible for flag verification. However, we quickly discovered that the application employed robust anti-Frida mechanisms.

The application consists of two native libraries:

- `libFreakyFrida.so`
- `libnative-lib.so`

One handles encryption and flag logic. The other acts as a security guardian, detecting Frida and blocking its operations at multiple stages (not sure).

When decompiling the APK with JADX, the Java layer reveals a straightforward implementation with two native libraries being loaded. The `FreakyFrid` class loads both `libFreakyFrida.so` and `libnative-lib.so`, suggesting a multi-layered native architecture where one library might be performing security checks while the other handles the core functionality.

## Analysis of the Java Layer

In the `FreakyFrid` class, we see the following Java code:

```java
package com.pwnsec;

import android.os.Bundle;
import android.util.Log;
import androidx.appcompat.app.AppCompatActivity;
import com.pwnsec.databinding.ActivityMainBinding;

/* loaded from: classes.dex */
public class FreakyFrid extends AppCompatActivity {
    private ActivityMainBinding binding;

    public native byte[] gXftm3iswpkVgBNDUp(byte[] bArr, byte b);

    public native String stringFromJNI(String str);

    static {
        System.loadLibrary("FreakyFrida");
        System.loadLibrary("native-lib");
    }

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        ActivityMainBinding inflate = ActivityMainBinding.inflate(getLayoutInflater());
        this.binding = inflate;
        setContentView(inflate.getRoot());
        this.binding.sampleText.setText("Welcome to PwnSec CTF 2025");
    }

    public void CheckAsYouLike(String str) {
        Log.d("Go Freaky Go Stupid: ", "Did you get the flag: " + stringFromJNI(str));
    }
}
```

The critical native function here is `stringFromJNI(String str)`, which is responsible for processing the input string and returning the flag if the input matches the expected value. To understand how the flag verification works, we need to analyze the implementation of this native function in `libFreakyFrida.so`.

## Analysis of `stringFromJNI`

```c
__int64 __fastcall Java_com_pwnsec_FreakyFrid_stringFromJNI(__int64 a1, __int64 a2, __int64 a3)
{
  __int64 v4; // r15
  void *v5; // r14
  size_t v6; // rbx
  char *v7; // r15
  std::ios_base *v8; // rbx
  __int64 (__fastcall **v9)(); // rax
  __int64 v10; // rax
  char *v11; // rbx
  __int64 v12; // rax
  unsigned __int8 *v13; // r15
  unsigned __int8 *v14; // r14
  __int64 v15; // rsi
  char *v16; // rbx
  __int64 v17; // r15
  __int128 v18; // xmm0
  __int128 v19; // xmm1
  __int128 v20; // xmm2
  std::ios_base *v21; // rbp
  __int64 (__fastcall **v22)(); // rax
  __int64 v23; // rax
  char *v24; // rbp
  __int64 v25; // rax
  __int64 i; // r14
  __int64 v27; // rsi
  int v28; // ebp
  const char *v29; // rsi
  __int64 v30; // r12
  char *s1; // [rsp+8h] [rbp-2E0h]
  _BYTE v33[16]; // [rsp+28h] [rbp-2C0h] BYREF
  void *ptr; // [rsp+38h] [rbp-2B0h]
  _QWORD v35[3]; // [rsp+40h] [rbp-2A8h] BYREF
  char v36[16]; // [rsp+58h] [rbp-290h] BYREF
  void *v37; // [rsp+68h] [rbp-280h]
  _QWORD dest[2]; // [rsp+70h] [rbp-278h] BYREF
  void *v39; // [rsp+80h] [rbp-268h]
  void *src; // [rsp+88h] [rbp-260h] BYREF
  unsigned __int8 *v41; // [rsp+90h] [rbp-258h]
  __int64 (__fastcall **v42)(); // [rsp+A0h] [rbp-248h] BYREF
  _QWORD v43[8]; // [rsp+A8h] [rbp-240h] BYREF
  __int128 v44; // [rsp+E8h] [rbp-200h]
  void *v45[2]; // [rsp+F8h] [rbp-1F0h]
  int v46; // [rsp+108h] [rbp-1E0h]
  _QWORD v47[19]; // [rsp+110h] [rbp-1D8h] BYREF
  __int64 (__fastcall **v48)(); // [rsp+1A8h] [rbp-140h] BYREF
  _QWORD v49[8]; // [rsp+1B0h] [rbp-138h] BYREF
  __int128 v50; // [rsp+1F0h] [rbp-F8h]
  void *v51[2]; // [rsp+200h] [rbp-E8h]
  int v52; // [rsp+210h] [rbp-D8h]
  _QWORD v53[26]; // [rsp+218h] [rbp-D0h] BYREF

  v53[19] = __readfsqword(0x28u);
  sub_61320();
  v4 = (*(__int64 (__fastcall **)(__int64, __int64, _QWORD))(*(_QWORD *)a1 + 1352LL))(a1, a3, 0);
  sub_61D80(&src);
  v5 = src;
  v6 = v41 - (_BYTE *)src;
  if ( (unsigned __int64)(v41 - (_BYTE *)src) >= 0xFFFFFFFFFFFFFFF0LL )
    Java_com_pwnsec_FreakyFrid_gXftm3iswpkVgBNDUp(dest);
  s1 = (char *)v4;
  if ( v6 >= 0x17 )
  {
    v7 = (char *)operator new((v6 | 0xF) + 1);
    v39 = v7;
    dest[0] = ((v6 | 0xF) + 1) | 1;
    dest[1] = v6;
    goto LABEL_6;
  }
  LOBYTE(dest[0]) = 2 * v6;
  v7 = (char *)dest + 1;
  if ( v41 != src )
LABEL_6:
    memmove(v7, v5, v6);
  v7[v6] = 0;
  v53[0] = off_CE3A0;
  v48 = &off_CE3E8;
  *(_QWORD *)((char *)&v49[-1] + (_QWORD)*(&off_CE3E8 - 3)) = off_CE410;
  v8 = (std::ios_base *)((char *)&v49[-1] + (_QWORD)*(v48 - 3));
  std::ios_base::init(v8, v49);
  *((_QWORD *)v8 + 17) = 0;
  *((_DWORD *)v8 + 36) = -1;
  v48 = &off_CE378;
  v53[0] = off_CE3A0;
  std::streambuf::basic_streambuf(v49);
  v49[0] = &off_CDE58;
  v50 = 0;
  *(_OWORD *)v51 = 0;
  v52 = 16;
  v9 = v48;
  *(_DWORD *)((char *)v49 + (_QWORD)*(v48 - 3)) = *(_DWORD *)((_BYTE *)v49 + (_QWORD)*(v48 - 3)) & 0xFFFFFFB5 | 8;
  v10 = (__int64)*(v9 - 3);
  v11 = (char *)&v49[-1] + v10;
  if ( *(_DWORD *)((char *)&v53[4] + v10) == -1 )
  {
    std::ios_base::getloc((std::ios_base *)&v42);
    v12 = std::locale::use_facet((std::locale *)&v42, (std::locale::id *)&std::ctype<char>::id);
    (*(void (__fastcall **)(__int64, __int64))(*(_QWORD *)v12 + 56LL))(v12, 32);
    std::locale::~locale((std::locale *)&v42);
  }
  *((_DWORD *)v11 + 36) = 48;
  v13 = (unsigned __int8 *)src;
  v14 = v41;
  if ( src != v41 )
  {
    do
    {
      v15 = *v13;
      *(_QWORD *)((char *)&v49[2] + (_QWORD)*(v48 - 3)) = 2;
      std::ostream::operator<<(&v48, v15);
      ++v13;
    }
    while ( v13 != v14 );
  }
  std::stringbuf::str(v36, v49);
  v16 = (char *)operator new(0x46u);
  v35[0] = v16;
  v35[2] = v16 + 70;
  *((_OWORD *)v16 + 3) = xmmword_43CE5;
  *((_OWORD *)v16 + 2) = xmmword_43CD5;
  *((_OWORD *)v16 + 1) = xmmword_43CC5;
  *(_OWORD *)v16 = xmmword_43CB5;
  *(_QWORD *)(v16 + 62) = 0x2911CD257449F1BDLL;
  v35[1] = v16 + 70;
  sub_61010(v35, dest);
  v17 = operator new(0x50u);
  *(_QWORD *)(v17 + 62) = *(_QWORD *)(v16 + 62);
  v18 = *(_OWORD *)v16;
  v19 = *((_OWORD *)v16 + 1);
  v20 = *((_OWORD *)v16 + 2);
  *(_OWORD *)(v17 + 48) = *((_OWORD *)v16 + 3);
  *(_OWORD *)(v17 + 32) = v20;
  *(_OWORD *)(v17 + 16) = v19;
  *(_OWORD *)v17 = v18;
  *(_BYTE *)(v17 + 70) = 0;
  v47[0] = off_CE3A0;
  v42 = &off_CE3E8;
  *(_QWORD *)((char *)&v43[-1] + (_QWORD)*(&off_CE3E8 - 3)) = off_CE410;
  v21 = (std::ios_base *)((char *)&v43[-1] + (_QWORD)*(v42 - 3));
  std::ios_base::init(v21, v43);
  *((_QWORD *)v21 + 17) = 0;
  *((_DWORD *)v21 + 36) = -1;
  v42 = &off_CE378;
  v47[0] = off_CE3A0;
  std::streambuf::basic_streambuf(v43);
  v43[0] = &off_CDE58;
  v44 = 0;
  *(_OWORD *)v45 = 0;
  v46 = 16;
  v22 = v42;
  *(_DWORD *)((char *)v43 + (_QWORD)*(v42 - 3)) = *(_DWORD *)((_BYTE *)v43 + (_QWORD)*(v42 - 3)) & 0xFFFFFFB5 | 8;
  v23 = (__int64)*(v22 - 3);
  v24 = (char *)&v43[-1] + v23;
  if ( *(_DWORD *)((char *)&v47[4] + v23) == -1 )
  {
    std::ios_base::getloc((std::ios_base *)v33);
    v25 = std::locale::use_facet((std::locale *)v33, (std::locale::id *)&std::ctype<char>::id);
    (*(void (__fastcall **)(__int64, __int64))(*(_QWORD *)v25 + 56LL))(v25, 32);
    std::locale::~locale((std::locale *)v33);
  }
  *((_DWORD *)v24 + 36) = 48;
  for ( i = 0; i != 70; ++i )
  {
    v27 = (unsigned __int8)v16[i];
    *(_QWORD *)((char *)&v43[2] + (_QWORD)*(v42 - 3)) = 2;
    std::ostream::operator<<(&v42, v27);
  }
  std::stringbuf::str(v33, v43);
  v28 = strcmp(s1, (const char *)v17);
  (*(void (__fastcall **)(__int64, __int64, char *))(*(_QWORD *)a1 + 1360LL))(a1, a3, s1);
  if ( v28 )
  {
    __android_log_print(4, "JNI_OnLoad_Check", "No match!");
    v29 = "LMAO, such a looser, you will be skill issued by TK";
  }
  else
  {
    __android_log_print(4, "JNI_OnLoad_Check", "Match!");
    v29 = "Yay you got the freaky flag";
  }
  v30 = (*(__int64 (__fastcall **)(__int64, const char *))(*(_QWORD *)a1 + 1336LL))(a1, v29);
  if ( (v33[0] & 1) != 0 )
    operator delete(ptr);
  v42 = &off_CE378;
  *(_QWORD *)((char *)&v43[-1] + (_QWORD)*(&off_CE378 - 3)) = off_CE3A0;
  v43[0] = &off_CDE58;
  if ( (v44 & 1) != 0 )
    operator delete(v45[0]);
  std::streambuf::~streambuf(v43);
  std::ostream::~ostream(&v42, &off_CE3B8);
  std::ios::~ios(v47);
  operator delete((void *)v17);
  operator delete(v16);
  if ( (v36[0] & 1) != 0 )
    operator delete(v37);
  v48 = &off_CE378;
  *(_QWORD *)((char *)&v49[-1] + (_QWORD)*(&off_CE378 - 3)) = off_CE3A0;
  v49[0] = &off_CDE58;
  if ( (v50 & 1) != 0 )
    operator delete(v51[0]);
  std::streambuf::~streambuf(v49);
  std::ostream::~ostream(&v48, &off_CE3B8);
  std::ios::~ios(v53);
  if ( (dest[0] & 1) != 0 )
    operator delete(v39);
  if ( src )
    operator delete(src);
  return v30;
}
```

The heart of the challenge lies within the `Java_com_pwnsec_FreakyFrid_stringFromJNI` function in `libFreakyFrida.so`. This function is responsible for validating the input string against an encrypted flag and returning the appropriate message based on whether the match succeeds or fails.

The challenge also employs RC4 encryption to protect both the flag and potentially the logic for checking the native-lib. The `sub_61D80` function serves as the key generator, creating a cryptographic key. This approach ensures that the key cannot be easily extracted through static analysis alone. The `sub_61010` function implements the RC4 encryption algorithm, which is a stream cipher that generates a keystream from the key and XORs it with the plaintext (or ciphertext) to produce the output.

The RC4 is used three times in total:

- In `JNI_OnLoad` for the native-lib library checking if its loaded correctly.
- In `stringFromJNI` to decrypt the expected flag for comparison.
- In `stringFromJNI` again to decrypt the native-lib library checking if its loaded correctly.

The most important line in this entire function is the comparison operation:

```c
v28 = strcmp(s1, (const char *)v17);
```

Here, `s1` is the input string provided by the user, and `v17` is the decrypted flag that the function generates through a series of operations. If the comparison returns zero (indicating a match), the function logs "Match!" and prepares to return the success message. Otherwise, it logs "No match!" and returns a failure message.

## Solution by PLT Hooking

We can employ a technique known as PLT (Procedure Linkage Table) hooking. This method allows us to intercept calls to specific functions in shared libraries, such as `strcmp()`, and redirect them to our custom implementation. By doing so, we can manipulate the behavior of the application without triggering its anti-tampering checks.

> Same issue as in RudeFrida, I cant use Frida to my Android Emulator :(

The first step is to decompile the APK to gain access to its internal structure. Using apktool, I extracted all the resources, manifest, and DEX bytecode in a form that can be modified and recompiled.

```sh
java -jar apktool_2.12.1.jar d FreakyFrida.apk -o FreakyFrida
```

This command decodes the APK file using apktool, extracting all resources, the AndroidManifest.xml, and converting the DEX bytecode to smali format for human-readable modification. The output directory `FreakyFrida` contains the complete decompiled project structure that can be edited and recompiled.

Next, We modify the smali code to inject a custom library loading instruction. We add code to below the existing `System.loadLibrary("FreakyFrida")` call to load our custom library named "ztzwashere".

```smali
const-string v0, "ztzwashere"

invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
```

These smali instructions create a string constant in register `v0` containing the name of our custom library "ztzwashere", then invoke the static method `System.loadLibrary()` to load it.

Additionally, We need to trigger the flag verification function since it's never called in the normal application flow. We can add code to the `onCreate` method to invoke `CheckAsYouLike()` with a dummy string:

```smali
const-string v0, "FreakyFrida"

invoke-virtual {p0, v0}, Lcom/pwnsec/FreakyFrid;->CheckAsYouLike(Ljava/lang/String;)V
```

For the PLT hooking implementation, We can use the [plthook](https://github.com/kubo/plthook/tree/master) library by kubo, which simplifies the process of replacing function pointers in the PLT. Below is the C code for our custom library `libztzwashere.so` that hooks `strcmp()`:

```c
#include <dlfcn.h>
#include <android/log.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>

#include "plthook.h"

#define LOG_TAG "ZTZWASHERE"

static ssize_t my_strcmp(const char *s1, const char *s2) 
{
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "my_strcmp called with %s and %s", s1, s2);
    return strcmp(s1, s2);
}

__attribute__((constructor))
void init() 
{
    void *handle = NULL;
    do 
    {
        handle = dlopen("libFreakyFrida.so", RTLD_LAZY);
        if (!handle) 
        {
            __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Failed to dlopen libFreakyFrida.so: %s", dlerror());
        }
    } while (0);

    void* strcmp_addr = dlsym(handle, "strcmp");
    if (!strcmp_addr) 
    {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Failed to dlsym strcmp");
        return;
    }

    plthook_t *plthook;
    if (plthook_open(&plthook, "libFreakyFrida.so") != 0) {
        printf("plthook_open error: %s\n", plthook_error());
        return;
    }

    if (plthook_replace(plthook, "strcmp", (void*)my_strcmp, NULL) != 0) {
        printf("plthook_replace error: %s\n", plthook_error());
        plthook_close(plthook);
        return;
    }
    plthook_close(plthook);
}
```

This C code defines a shared library that uses the `constructor` attribute to specify an `init()` function that runs automatically when the library is loaded. Inside `init()`, it attempts to obtain a handle to the already-loaded `libFreakyFrida.so` using `dlopen()` with the `RTLD_NOLOAD` flag, which prevents loading a new instance if it's already loaded. It then retrieves the address of the `strcmp()` function using `dlsym()`. Finally, it calls `plthook_replace()` to replace the PLT entry for `strcmp()` with our custom `my_strcmp()` function, which logs the input strings and calls the original `strcmp()` to maintain normal behavior.

To compile this custom library, We need to create the Android NDK build configuration files. The build system requires two configuration files: `Android.mk` and `Application.mk`.

```makefile
# filename: jni/Android.mk
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := ztzwashere
LOCAL_SRC_FILES := main.c plthook_elf.c
LOCAL_LDLIBS := -llog -ldl
include $(BUILD_SHARED_LIBRARY)
```

The `Android.mk` file defines the build rules for our module.

```makefile
# filename: jni/Application.mk
APP_ABI := x86_64
APP_PLATFORM := android-21
APP_STL := c++_static
```

The `Application.mk` file specifies application-wide build settings. We needed to set the target architecture to `x86_64` to match the original application's architecture.

With the configuration in place, We can compile the custom library using the NDK build command:

```sh
ndk-build
```

After building the custom library, We copy the compiled `.so` file into the decompiled APK's library directory at `lib/x86_64/libztzwashere.so`. With all modifications in place, we recompile the APK, aligned it for optimization, and signed it with a development certificate:

```sh
java -jar .\apktool_2.12.1.jar b FreakyFrida -o FreakyFrida.patched.apk
zipalign -p 4 FreakyFrida.patched.apk FreakyFrida.aligned.apk
apksigner sign -v --ks ./HEXTREE.keystore --ks-key-alias HEXTREE --v2-signing-enabled true FreakyFrida.aligned.apk
```

Finally, installing the modified APK on an emulator or device and running it triggers our PLT hook. The application loads normally, and when the flag verification function is called, our hooked `strcmp()` function executes instead, logging the input strings and calling the original comparison function.

```sh
adb logcat | grep ZTZWASHERE
```

The log output confirms that our hook is functioning correctly, showing the parameters passed to `my_strcmp()` and ultimately leading to the successful retrieval of the flag.
