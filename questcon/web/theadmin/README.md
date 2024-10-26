---
category: Web Exploitation
tags: 
  - jwt
---

# Theadmin

## Scenario

> The Professor has left a vulnerable authentication system. Can you exploit it and gain admin not just using admin? Sometimes the simplest loopholes can lead to the biggest breakthroughs. Its simple but **none** of you could figure out.

## Solution

You need to send a POST request to the `https://<url>/auth` endpoint with the username `admin`. The server will respond with a JSON object containing a token. This token is a JSON Web Token (JWT) that is base64 encoded and consists of three parts separated by a dot (`.`): the header, the payload, and the signature. You should create a new header with the algorithm set to `none` and the type set to `JWT`. Then, decode the payload from the token and create a new payload. After that, encode the new header and the new payload separately. Finally, send a GET request to the `https://<url>/access` endpoint with the new header and the new payload.

## Flag

`QUESTCON{J3T_4lg0r1thm_15_vuln3r4bl3_70_n0n3}`
