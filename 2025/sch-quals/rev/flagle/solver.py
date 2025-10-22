from pwn import process
from concurrent.futures import ThreadPoolExecutor, as_completed
import os

TOTAL_LEN = 59
PREFIX = "SCH25{since_when_did_wordle_became_this_annoying_"
CHARSET = "_{}0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
MAX_WORKERS = min(32, (os.cpu_count() or 4) * 2)

flag = PREFIX

def try_candidate(c, attempt):
    p = process("./flagle")
    try:
        p.sendline(attempt)
        resp = p.recvall(timeout=2).decode(errors="ignore")
        green_count = resp.count("🟩")
    except Exception:
        green_count = -1
        resp = ""
    finally:
        try:
            p.close()
        except Exception:
            pass
    return c, green_count, resp

while True:
    threshold = len(flag) - 1
    attempts = [(c, flag + c + "A" * (TOTAL_LEN - len(flag) - 1)) for c in CHARSET]

    found_char = None
    found_resp = None

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(try_candidate, c, att): c for c, att in attempts}
        for fut in as_completed(futures):
            c, green_count, resp = fut.result()
            print(f"Tried {c!r}: {green_count} greens")
            if green_count > threshold:
                found_char = c
                found_resp = resp
                break

    if found_char:
        flag += found_char
        print(f"Found next char: {found_char}, flag so far: {flag}")
        # continue to next position
    else:
        print("No valid character found, stopping.")
        break
