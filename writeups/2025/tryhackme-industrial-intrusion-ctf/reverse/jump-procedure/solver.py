from pwn import *

BINARY = './jmpproc'

context.binary = BINARY
# context.log_level = 'debug'

def final_acc(pid, skip, bound):
    out = b'Procedure Error'
    try:
        p = process(BINARY)
        p.sendlineafter(b'Process ID: ', str(pid).encode())
        p.sendlineafter(b'Skip bytes proc: ', str(skip).encode())
        p.sendlineafter(b'Process bound: ', str(bound).encode())
        out = p.recvline().strip()
    except Exception as e:
        log.failure(f"Error occurred: {e}")

    p.close()
    return out != b'Procedure Error'

for pid in range(20):
    for skip in range(150):
        for bound in range(240):
            log.info(f'Testing PID: {pid}, Skip: {skip}, Bound: {bound}')
            if final_acc(pid, skip, bound):
                print(pid, skip, bound)
                break
