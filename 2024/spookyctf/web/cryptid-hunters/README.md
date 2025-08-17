---
title: cryptid-hunters
categories: "Web Exploitation"
tags: 
  - sqli
draft: false
completedDuringEvent: true
submitted: true
flags: NICC{1N_PuRSu1T_0F_4LL13S}
---
## Scenario

> The intern found some web traffic originating from a known Consortium IP to this website. The website looks like a 7th grader's project.
>
> Most of NICC took a look at it and blew it off, but Maya thinks there may be something worth looking into. Mary and the others tell her they are too busy and it is a waste of time. She is getting pretty sick and tired of no one taking her seriously. If she finds a lead she is going to follow it. NICC needs all the help they can get, whether its a Sasquatch or a giant clam!

By [_m4ch3t3](https://github.com/mmgajda)

## Hints

<details>
<summary>Hint 1</summary>

The hunters' webmaster is very tech illiterate. It seems like he just followed some intro level tutorial or used some free AI tool for the code.
</details>

## Solution

![image.png](image.png)

Well another SQL injection challenge. This time we have a simple login form. We can try to login with some random credentials and see what happens. We can see that the page returns `Invalid username or password` if we enter wrong credentials. We can try to login with `' OR 1=1 --` as the username and password. This will return list of cryptids. The flag is hidden in the list of cryptids.
