---
title: CuteFrida
categories: Mobile
authors: TK
tags: 
draft: false
completedDuringEvent: true
submitted: true
points: 215
solves: 57
flags: flag{7he_developer_is_S0_p4r4n01d_1t_th1nk5_Fr1d4_1s_3v3rywh3r3}
---

> This app is so cute yet so susy, isn't it?

---

The app contains an encrypted flag stored in the `What_do_you_mean_by_encrypted_flag` variable in `MainActivity.java`. The flag is obfuscated using a custom random number generator and a deobfuscation algorithm defined in the `com.joom.paranoid` package.

## Analysis

Since im not the one who solved this challenge but my teammate SeaSir?! (boppind) did, I will explain as his perspective.

The MainActivity.java file contains the following code:

```java filename=/com/pwnsec/cutefrida/MainActivity.java
package com.pwnsec.cutefrida;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.OnApplyWindowInsetsListener;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import com.joom.paranoid.Deobfuscator$app$Release;

/* loaded from: classes.dex */
public class MainActivity extends AppCompatActivity {
    private static final String What_do_you_mean_by_encrypted_flag = Deobfuscator$app$Release.getString(-548601664941L);

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        EdgeToEdge.enable(this);
        setContentView(C0814R.layout.activity_main);
        String.format(Deobfuscator$app$Release.getString(-3140818349L), Deobfuscator$app$Release.getString(-28910622125L));
        Log.d(Deobfuscator$app$Release.getString(-308083496365L), Deobfuscator$app$Release.getString(-338148267437L));
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(C0814R.id.main), new OnApplyWindowInsetsListener() { // from class: com.pwnsec.cutefrida.MainActivity$$ExternalSyntheticLambda0
            @Override // androidx.core.view.OnApplyWindowInsetsListener
            public final WindowInsetsCompat onApplyWindowInsets(View view, WindowInsetsCompat windowInsetsCompat) {
                return MainActivity.lambda$onCreate$0(view, windowInsetsCompat);
            }
        });
    }

    static /* synthetic */ WindowInsetsCompat lambda$onCreate$0(View view, WindowInsetsCompat windowInsetsCompat) {
        Insets insets = windowInsetsCompat.getInsets(WindowInsetsCompat.Type.systemBars());
        view.setPadding(insets.left, insets.top, insets.right, insets.bottom);
        return windowInsetsCompat;
    }
}
```

All the strings in the MainActivity are obfuscated using the Deobfuscator$app$Release class from the `com.joom.paranoid` package. The encrypted flag is stored in the `What_do_you_mean_by_encrypted_flag` variable, which is decrypted using the `Deobfuscator$app$Release.getString` method with the seed `-548601664941L`.

```java
private static final String What_do_you_mean_by_encrypted_flag = Deobfuscator$app$Release.getString(-548601664941L);
```

The deobfuscation process involves two main classes: `RandomHelper` and `DeobfuscatorHelper`. The `RandomHelper` class implements a custom random number generator, while the `DeobfuscatorHelper` class uses that generator to decrypt the obfuscated strings.

```java filename=/com/joom/paranoid/RandomHelper.java
package com.joom.paranoid;

/* loaded from: classes.dex */
public class RandomHelper {
    private static short rotl(short s, int i) {
        return (short) ((s >>> (32 - i)) | (s << i));
    }

    public static long seed(long j) {
        long j2 = (j ^ (j >>> 33)) * 7109453100751455733L;
        return ((j2 ^ (j2 >>> 28)) * (-3808689974395783757L)) >>> 32;
    }

    private RandomHelper() {
    }

    public static long next(long j) {
        short s = (short) (j & 65535);
        short s2 = (short) ((j >>> 16) & 65535);
        short rotl = (short) (rotl((short) (s + s2), 9) + s);
        short s3 = (short) (s2 ^ s);
        return ((rotl(s3, 10) | (rotl << 16)) << 16) | ((short) (((short) (rotl(s, 13) ^ s3)) ^ (s3 << 5)));
    }
}
```

```java filename=/com/joom/paranoid/DeobfuscatorHelper.java
package com.joom.paranoid;

/* loaded from: classes.dex */
public class DeobfuscatorHelper {
    public static final int MAX_CHUNK_LENGTH = 8191;

    private DeobfuscatorHelper() {
    }

    public static String getString(long j, String[] strArr) {
        long next = RandomHelper.next(RandomHelper.seed(4294967295L & j));
        long j2 = (next >>> 32) & 65535;
        long next2 = RandomHelper.next(next);
        int i = (int) (((j >>> 32) ^ j2) ^ ((next2 >>> 16) & (-65536)));
        long charAt = getCharAt(i, strArr, next2);
        int i2 = (int) ((charAt >>> 32) & 65535);
        char[] cArr = new char[i2];
        for (int i3 = 0; i3 < i2; i3++) {
            charAt = getCharAt(i + i3 + 1, strArr, charAt);
            cArr[i3] = (char) ((charAt >>> 32) & 65535);
        }
        return new String(cArr);
    }

    private static long getCharAt(int i, String[] strArr, long j) {
        return (strArr[i / MAX_CHUNK_LENGTH].charAt(i % MAX_CHUNK_LENGTH) << 32) ^ RandomHelper.next(j);
    }
}
```

The deobfuscation process involves seeding a custom random number generator with a modified version of the input seed. The generator produces pseudo-random values that are used to reconstruct the original string character by character. The `getString` method retrieves the length of the string and then iteratively fetches each character using the `getCharAt` method, which combines the character's value with the next random number generated.

```java filename=/com/joom/paranoid/Deobfuscator$app$Release.java
package com.joom.paranoid;

/* loaded from: classes.dex */
public class Deobfuscator$app$Release {
    private static final String[] chunks = {"\ufffaﾮￅ\uffdfￚﾌ\uffbfﾙﾓﾞﾘﾄ\uffc8ﾗﾚﾠﾛﾚﾉﾚﾓﾐﾏﾚﾍﾠﾖﾌﾠﾬￏﾠﾏￋﾍￋﾑￏￎﾛﾠￎﾋﾠﾋﾗￎﾑﾔￊﾠﾹﾍￎﾛￋﾠￎﾌﾠￌﾉￌﾍﾆﾈﾗￌﾍￌﾂ\ufff9ﾷﾖﾑﾋￅ\uffdfￏﾼﾗﾚﾜﾔ\uffdfﾋﾗﾚ\uffdfﾞﾌﾌﾚﾋ\uffdfﾙﾐﾓﾛﾚﾍￓ\uffdfﾆﾐﾊ\uffdfﾒﾖﾘﾗﾋ\uffdfﾙﾖﾑﾛ\uffdfﾌﾐﾒﾚﾋﾗﾖﾑﾘ\ufffaﾮￅ\uffdfￚﾌ"};

    public static String getString(long j) {
        return DeobfuscatorHelper.getString(j, chunks);
    }
}
```

The obfuscated strings are stored in chunks, and the `getString` method retrieves the appropriate chunk based on the input seed. The deobfuscation process reconstructs the original string using the custom random number generator and the character retrieval method.

## Solution by Reconstructing the Deobfuscation Algorithm

Solver by my teammate SeaSir?! (boppind):

```py
s = "\ufffa\uffae\uffc5\uffdf\uffda\uff8c\uffbf\uff99\uff93\uff9e\uff98\uff84\uffc8\uff97\uff9a\uffa0\uff9b\uff9a\uff89\uff9a\uff93\uff90\uff8f\uff9a\uff8d\uffa0\uff96\uff8c\uffa0\uffac\uffcf\uffa0\uff8f\uffcb\uff8d\uffcb\uff91\uffcf\uffce\uff9b\uffa0\uffce\uff8b\uffa0\uff8b\uff97\uffce\u0091\u0094\u00ca\u00a0\u00b9\u008d\u00ce\u009b\u00cb\u00a0\u00ce\u008c\u00a0\u00cc\u0089\u00cc\u008d\u0086\u0088\u0097\u00cc\u008d\u00cc\u0082\u00f9\u00b7\u0096\u0091\u008b\u00c5\u00df\u00cf\u00bc\u0097\u009a\u009c\u0094\u00df\u008b\u0097\u009a\u00df\u009e\u008c\u008c\u009a\u008b\u00df\u0099\u0090\u0093\u009b\u009a\u008d\u00d3\u00df\u0086\u0090\u008a\u00df\u0092\u0096\u0098\u0097\u008b\u00df\u0099\u0096\u0091\u009b\u00df\u008c\u0090\u0092\u009a\u008b\u0097\u0096\u0091\u0098\u00fa\u00ae\u00c5\u00df\u00da\u008c"

MASK64 = (1 << 64) - 1

def rotl16(x, n):
    n %= 16
    return ((x << n) & 0xffff) | ((x & 0xffff) >> (16 - n))

def seed(j):
    j &= MASK64
    v0 = (j >> 33) & MASK64
    j ^= v0
    j = (j * 0x62a9d9ed799705f5) & MASK64
    v0 = (j >> 28) & MASK64
    j ^= v0
    j = (j * ((-0x34db2f5a3773ca4d) & MASK64)) & MASK64
    v0 = (j >> 32) & MASK64
    j ^= v0
    return j & MASK64

def next_rand(j):
    j &= MASK64
    mask = 0xffff

    v2 = j & mask
    p0 = (j >> 16) & mask

    p1 = (v2 + p0) & 0xffff
    p1 = rotl16(p1, 9)
    p1 = (p1 + v2) & 0xffff

    p0_xor = p0 ^ v2

    v0 = rotl16(v2, 13)
    v0 ^= p0_xor
    v0 &= 0xffff

    v1 = (p0 << 5) & 0xffff
    v0 ^= v1

    p0 = rotl16(p0, 10)

    high = p1 & 0xffff
    res = ((high << 32) & MASK64) | ((p0 & 0xffff) << 16) | (v0 & 0xffff)
    return res & MASK64

def getCharAt_single(i, s, j):
    rnd = next_rand(j)
    pos = i % len(s)
    c = ord(s[pos]) & 0xffff
    val = (c << 32) ^ rnd
    return val & MASK64

def getString_lowbytes(j, s):
    j &= MASK64
    v = seed(j)

    # derive p0
    v = next_rand(v)
    ushr32 = (v >> 32) & 0xffff
    v = next_rand(v)
    ushr16 = (v >> 16) & 0xffff0000

    p0 = (((j >> 32) & MASK64) ^ ushr32 ^ (ushr16 >> 16)) & 0xffffffff

    # first call gives us length
    val = getCharAt_single(p0, s, j)
    length = (val >> 32) & 0xffff

    out = []
    for k in range(length):
        idx = p0 + k + 1
        val = getCharAt_single(idx, s, j)
        ch = (val >> 32) & 0xffff
        out.append(ch & 0xff)

    return bytes(out)

# candidate 64-bit seeds (from reversing)
keys = [
    -0x7fbb3515ad,
    -0xbb3515ad,
    -0x6bb3515ad,
    -0x47bb3515ad,
    -0x4ebb3515ad,
]

import re

for k in keys:
    j = k & MASK64
    b = getString_lowbytes(j, s)
    print('--- KEY', hex(j), 'LEN', len(b))

    hits = 0
    for key in range(1, 256):
        xb = bytes(c ^ key for c in b)
        if re.search(b'(?i)(ctf|flag)', xb):
            m = re.search(rb'[\x20-\x7e]{8,}', xb)
            if m:
                snippet = m.group(0).decode('ascii', errors='ignore')
            else:
                snippet = xb[:80].hex()
            print('XOR', hex(key), 'FOUND_SNIPPET:', snippet)
            hits += 1

    if hits == 0:
        for m in re.finditer(rb'[\x20-\x7e]{8,}', b):
            print('PLAINTEXT_CAND:', m.group(0).decode('ascii', errors='ignore'))
            break
```

## Solution with Frida

To extract the flag using Frida, we can hook into the `onCreate` method of the `MainActivity` class and retrieve the value of the `What_do_you_mean_by_encrypted_flag` variable after it has been decrypted. Below is a Frida script that accomplishes this:

> Or you can just log the variable directly by decompiling the APK and editing the smali code to print it out.
>
> ```smali
> sget-object v0, Lcom/pwnsec/cutefrida/MainActivity;->What_do_you_mean_by_encrypted_flag:Ljava/lang/String;
>
> invoke-static {v0}, Landroid/util/Log;->d(Ljava/lang/String;)I
> ```
>
> Inject this code snippet into the `onCreate` method of MainActivity.smali to log the decrypted flag.

Here's the Frida script:

```js
Java.perform(function () {
    var MainActivity = Java.use('com.pwnsec.cutefrida.MainActivity');

    MainActivity.onCreate.overload('android.os.Bundle').implementation = function (bundle) {
        this.onCreate(bundle);

        var flag = MainActivity.What_do_you_mean_by_encrypted_flag.value;
        console.log('Decrypted Flag: ' + flag);
    };
});
```
