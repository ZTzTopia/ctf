---
title: "Marks the Spot"
categories: Miscellaneous
tags: 
draft: false
completedDuringEvent: true
submitted: true
flag: CIT{YBF4Y6M6P}
---
> > 3D*=H1,:U?.l&je6W$Z;1,:U?.l&je6V:H?1,:U?.l&je6V&t)1,:U?.l&je6V(<U=>Eu6.p+P66V'461,:U?.l&je6W$?41,:U?.l&j
>
> Flag Format: CIT{example_flag}

by `ronnie`

---

Given `Base85` encoded string, the decoded string is:

```
9JVM2222+22
CQP52222+22
CJX82222+22
CH2J2222+22
CHXPX2X2+X2
CH9P2222+22
CQG72222+22
```

We can convert the Open Location/Plus Code to coordinates with [dCode Plus Code Converter](https://www.dcode.fr/open-location-code) and the coordinates are:

```
9JVM2222+22 -> 67.0000625, 73.0000625
CQP52222+22 -> 84.0000625, 123.0000625
CJX82222+22 -> 89.0000625, 66.0000625
CH2J2222+22 -> 70.0000625, 52.0000625
CHXPX2X2+X2 -> 89.9999375, 54.0000625
CH9P2222+22 -> 77.0000625, 54.0000625
CQG72222+22 -> 80.0000625, 125.0000625
```

Noticed that in the coordinates there is `123` and `125` which are the `ASCII` values for `{` and `}` respectively. So i decided to convert the coordinates to `ASCII` values.

```
67 73 84 123 89 66 70 52 89 54 77 54 80 125
```

Then we converted the `ASCII` values to characters and got the flag.
