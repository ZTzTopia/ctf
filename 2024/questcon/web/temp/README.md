---
title: Temp
categories: "Web Exploitation"
tags: 
  - SSRF
draft: true
completedDuringEvent: true
submitted: true
flags: flag: QUESTCON{r3c0ver_d3l3t3d_fil3}
---
## Scenario

> Professor deleted a file !oops Can you find the file for him?

## Solution

The website is SSRF File Reader, which allows you to read files on the server. The challenge provides a URL to read the file `flag.txt` on the server. The URL is `http://<url>/?url=file:///flag.txt`. The file `flag.txt` does not exist on the server. However, we can read the file `flag.txt` by changing the URL to `http://<url>/?url=file:///flag.txt%00`. The `%00` is a null byte that terminates the string and allows us to read the file `flag.txt`.
