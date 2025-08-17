---
title: Orbiter
categories: Web Exploitation
tags: 
draft: false
completedDuringEvent: true
submitted: true
flags: flag: IFEST13{345Y_P34SY_L3M0N_5QU332Y}
---
> 3 people go to the moon, keep in communication with them
>
> URL : http://103.163.139.198:8181/

by `sipoer`

---

Opening the website, we are presented with the following page:

![alt text](image.png)

## First Flag

If you pay attention, we will be redirected to `http://103.163.139.198:8181/login.php`.

And yes, since this website uses `PHP`, we can try `phpinfo.php` to see more information about the server. From here, we can view all the server information.

Casually searching for flags on this page, we can see the variables `FLAG-ID`, `FLAG-PASS-TRUE`, and `SECRET-FLAG` set within the `$_SERVER` variable.

![alt text](image-1.png)

When decoding `SECRET-FLAG`, we get the first flag `(1)345Y_P34SY`.

## Third Flag

Since `Armstrong` and `345Y_P34SY` are included in the information, we can try logging in using `Armstrong` as the username and `345Y_P34SY` as the password.

* **Username:** Armstrong
* **Password:** 345Y\_P34SY

After logging in, we are taken to the communication page, where there is a **Communication Checker Tool** that allows us to ping an IP address.

We can try performing a `Command Injection` in this input field:

```
127.0.0.1;ls
```

![alt text](image-2.png)

We can see the result from the `ls` command we entered in the field.

Among the listed files, we find a file named `true_flag.txt`. Let's try reading it.

![alt text](image-3.png)

This reveals the third flag: `(3)5QU332Y`.

## Second Flag

Since I had no clue, I decided to check the cookies because there is a login, so cookies must be set.

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6IkFybXN0cm9uZyIsInBhc3N3b3JkIjoiMzQ1WV9QMzRTWSIsImZsYWciOiIoMilfTDNNME5fIiwiZXhwIjoxNzQ2OTczMzk4fQ.e0RX_ErpVBGzj4NxBZL4515yMgex6QOpI-Iidc9CuM0
```

After decoding it, we get the following result:

`{"username":"Armstrong","password":"345Y_P34SY","flag":"(2)_L3M0N_","exp":1746973398}`

Thus, we obtain the second flag: `(2)_L3M0N_`.
