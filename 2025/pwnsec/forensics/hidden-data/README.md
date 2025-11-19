---
title: HiddenData
categories: Forensics
authors: Abdullah
tags: 
draft: false
completedDuringEvent: true
submitted: true
points: 385
solves: 23
flags: flag{12d65e001866f854c23a48f0d47957ed}
---

> Just chatting https://master-platform-bucket.s3.us-east-1.amazonaws.com/challenge_resources/HiddenData.zip

---

This challenge provided a Windows user directory that looked ordinary, but the key artifacts were scattered across several common application stores. Our first step was to examine the browser history located in `Windows\AppData\Local\Microsoft\Edge\User Data\Default\History`, since browser activity often hints at what the user installed or accessed recently. Inside the SQLite database, we identified visits to download pages for Discord, WinRAR, and Zoom.

Because Discord appeared in the history, we turned our attention to its cache directory. Discord, being an Electron application, keeps Chromium-style cached objects under `Windows\AppData\Roaming\discord\Cache\Cache_Data`. These cache files frequently contain JSON fragments of messages, images, or other temporary objects. Using [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) to parse them, we found cached Discord message content, including a sequence of messages that implied sensitive data had just been shared:

```
"Got it I'll copy it now"
"Here’s the secret link — https://pastebin.com/AAGyxC3p"
"After 5 minutes, the password will be deleted."
```

The mention of copying immediately suggested clipboard artifacts. After some research on Google, I found an article ([How to Perform Clipboard Forensics: ActivitiesCache.db, Memory Forensics and Clipboard History](https://www.inversecos.com/2022/05/how-to-perform-clipboard-forensics.html)) indicating that Windows 10 and later versions store clipboard history in a database file located at:

```
Windows\AppData\Local\ConnectedDevicesPlatform\e519ce15b823079b\ActivitiesCache.db
```

This file is an SQLite database containing tables related to activity history, including clipboard operations. After opening it with DB Browser for SQLite, we examined the tables like `SmartLookup`. The `SmartLookup` table proved most useful, as it stores serialized clipboard payloads, often Base64-encoded inside JSON structures.

One entry contained a suspicious payload inside the `ClipboardPayload` field:

```json
[{"content":"VGgxJF8xJF9yM0BsX3BAJCR3MHJkIQ==","formatName":"Text"}]
```

Decoding the Base64 value revealed:

```
Th1$_1$_r3@l_p@$$w0rd!
```

This password was likely the key to accessing the Pastebin link mentioned in the Discord messages. Using this password, we successfully accessed the Pastebin content, which contained the flag for the challenge.
