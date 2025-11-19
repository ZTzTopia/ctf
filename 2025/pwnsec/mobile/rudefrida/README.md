---
title: RudeFrida
categories: Mobile
authors: TK
tags: 
draft: false
completedDuringEvent: true
submitted: true
points: 390
solves: 22
flags: flag{w3_l4ugh3d_4t_y0ur_Fr1d4_scr1p7_but_it_st1ll_w0rk5_lol}
---

> Say hello to RudeFrida, it is like your toxic ex who gaslighted you for loving her.

---

Given an Android application that implements anti-Frida and anti-rooting mechanisms in its native library, our goal is to extract the hidden flag without being detected by these protections.

> I initially attempted to use Frida by injecting the `frida-gadget.so` into the app, but my Frida instance could not connect to the application because it failed to create a network connection. So I decided to use other methods to get the flag.

## Analyzing the Application

When decompiled with JADX, the Java layer reveals minimal logic. The `MainActivity` class simply loads a native library named "Rudefrida" and calls a JNI function `stringFromJNI()` which returns a sarcastic message.

```java
package com.pwnsec.RudeFrida;

import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import com.pwnsec.RudeFrida.databinding.ActivityMainBinding;

/* loaded from: classes.dex */
public class MainActivity extends AppCompatActivity {
    private ActivityMainBinding binding;

    public native String stringFromJNI();

    static {
        System.loadLibrary("Rudefrida");
    }

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        Toast.makeText(this, "Oh look, a clown 🤡", 1).show();
        ActivityMainBinding inflate = ActivityMainBinding.inflate(getLayoutInflater());
        this.binding = inflate;
        setContentView(inflate.getRoot());
        Log.d("RudeFrida: ", stringFromJNI());
    }
}
```

## Examining the Native Library

Moving to the native layer, I opened the `libRudefrida.so` file in a disassembler to examine the actual implementation. The native library contains several protection mechanisms that work in concert to detect tampering attempts. The `JNI_OnLoad()` function is the first to execute when the library loads, serving as an initialization point where early security checks can be performed before any application code runs.

```c
__int64 JNI_OnLoad()
{
  __android_log_print(
    4,
    "RudeFrida",
    "Well Hello bozo, I hope your not here for the flag or smth. Fine fine, the flag is here yes, but can you pass the phantom of frida");
  FridaCheck();
  return 65542;
}
```

Also there is `.init_array` section that contains constructor functions that execute automatically when the library is loaded, before any other code runs. One of these constructors also calls `FridaCheck()` to reinforce the anti-Frida protection at multiple stages of the library's lifecycle.

The `Java_com_pwnsec_RudeFrida_MainActivity_stringFromJNI()` function is the JNI method that corresponds to the `stringFromJNI()` declaration in the Java code. This function serves as the bridge between the Java and native layers, and it also performs security checks before returning the mocking message to the caller.

```c
__int64 __fastcall Java_com_pwnsec_RudeFrida_MainActivity_stringFromJNI(__int64 a1)
{
  char *v1; // rbx
  __int64 v2; // r14

  is_rooted_simple();
  FridaCheck();
  v1 = (char *)operator new(0x30u);
  strcpy(v1, "Oh look — another Frida enthusiast. Cute.");
  v2 = (*(__int64 (__fastcall **)(__int64, char *))(*(_QWORD *)a1 + 1336LL))(a1, v1);
  operator delete(v1);
  return v2;
}
```

The core of the anti-Frida protection is implemented in the `FridaCheck()` function, which detects Frida by monitoring network connections on specific ports.

The anti-rooting protection is implemented in the `is_rooted_simple()` function, which checks for the presence of the `su` binary in multiple common locations.

While examining the native library, There is a particular function that caught attention: `get_flag()`. This function appears to be responsible for generating or retrieving the flag, but it is not called from anywhere within the library. This suggests that it may be intended for external invocation, possibly through Frida or another method.

```c
unsigned __int64 __fastcall get_flag(int a1, int a2)
```

The function signature reveals that `get_flag()` takes two integer parameters. Through further analysis of the disassembled code, I determined that the function checks whether `a1 + a2` equals 1337. If the validation passes, the function processes and returns the flag.

## Calling the Function Through Library Injection

Rather than fighting the anti-Frida and anti-rooting protections head-on, I devised a solution that would operate entirely within the application's own process space. By injecting a custom native library into the application, I could execute code that calls `get_flag()` directly without triggering the network-based Frida detection or requiring root access.

The first step is to decompile the APK to gain access to its internal structure. Using apktool, I extracted all the resources, manifest, and DEX bytecode in a form that can be modified and recompiled.

```sh
java -jar apktool_2.12.1.jar d RudeFrida.apk -o RudeFrida
```

Next, We modify the smali code to inject a custom library loading instruction. We add code to below the existing `System.loadLibrary("Rudefrida")` call to load our custom library named "ztzwashere".

```smali filename=smali/com/pwnsec/RudeFrida/MainActivity.smali
const-string v0, "ztzwashere"

invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
```

These smali instructions create a string constant in register `v0` containing the name of our custom library "ztzwashere", then invoke the static method `System.loadLibrary()` to load it.

With the injection point established, We can create a custom native library that would execute automatically when loaded.

```c filename=jni/main.c
#include <dlfcn.h>
#include <android/log.h>
#include <stdio.h>

#define LOG_TAG "ZTZWASHERE"

typedef unsigned long long (*get_flag_t)(int, int);

__attribute__((constructor))
void init() 
{
    void *handle = NULL;
    do 
    {
        handle = dlopen("libRudefrida.so", RTLD_NOLOAD);
        if (!handle) 
        {
            __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Failed to dlopen libRudefrida.so: %s", dlerror());
            break;
        }
    } while (0);

    get_flag_t get_flag = (get_flag_t)dlsym(handle, "_Z8get_flagii");
    if (!get_flag) 
    {
        get_flag_t get_flag = (get_flag_t)((unsigned long long)handle + 0x00000000000618E0);
        if (!get_flag) 
        {
            __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Failed to dlsym get_flag");
            return;
        }
    }

    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "Calling get_flag...");

    unsigned long long res = get_flag(1000, 337);
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "get_flag returned: 0x%llx", res);
}
```

This C code defines a shared library that uses the `constructor` attribute to specify an `init()` function that runs automatically when the library is loaded. Inside `init()`, it attempts to obtain a handle to the already-loaded `libRudefrida.so` using `dlopen()` with the `RTLD_NOLOAD` flag, which prevents loading a new instance if it's already loaded. It then retrieves the address of the `get_flag()` function using `dlsym()`. Finally, it calls `get_flag(1000, 337)` and logs the returned value.

To compile this custom library, We need to create the Android NDK build configuration files. The build system requires two configuration files: `Android.mk` and `Application.mk`.

```makefile filename=jni/Android.mk
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := ztzwashere
LOCAL_SRC_FILES := main.c
LOCAL_LDLIBS := -llog -ldl
include $(BUILD_SHARED_LIBRARY)
```

The `Android.mk` file defines the build rules for our module.

```makefile filename=jni/Application.mk
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
java -jar .\apktool_2.12.1.jar b RudeFrida -o RudeFrida.patched.apk
zipalign -p 4 RudeFrida.patched.apk RudeFrida.aligned.apk
apksigner sign -v --ks ./HEXTREE.keystore --ks-key-alias HEXTREE --v2-signing-enabled true RudeFrida.aligned.apk
```

When the modified APK is installed and launched, the injection sequence executes seamlessly. The custom library loads, retrieves the `get_flag()` function, and calls it with the correct parameters. The flag is logged in the Android logcat output, to run adb logcat and filter for our custom tag:

```sh
adb logcat -s "ZTZWASHERE"
```

The log output reveals the flag returned by the `get_flag()` functionn.
