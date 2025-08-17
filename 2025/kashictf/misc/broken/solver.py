from pwn import *
import hlextend

# context.log_level = 'debug'

s = hlextend.new('sha1')

for i in range(4, 32):
    r = remote('kashictf.iitbhucybersec.in', 26438)

    new_message = s.extend(b'&file=flag.txt', b'count=10&lat=37.351&user_id=1&long=-119.827&file=random.txt', i, '01be4a249bed4886b93d380daba91eb4a0b1ee29')
    new_message = new_message.decode("latin-1")
    new_message = new_message.encode("unicode_escape")

    new_hash = s.hexdigest()

    r.recvuntil(b'Example: count=10&lat=37.351&user_id=1&long=-119.827&file=random.txt|01be4a249bed4886b93d380daba91eb4a0b1ee29\n')
    r.send(flat([
        new_message,
         b'|',
          new_hash.encode()
    ]))

    if b'Invalid HMAC' not in r.recvline():
        print(f'Found key length: {i}')
        r.interactive()
        break

    r.close()
