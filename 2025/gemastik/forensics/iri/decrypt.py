from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

ct = bytes.fromhex('eade7b7579fb9e4cd86f38e7d84418230e4b042e9c593e6e6038f725c19b5cd818377dcb95c2c998662edac817d07cbe502bb582085b93529f2acdf46ef19abc6529bf6204222b8a93cb3dbe8d8b4294e6a33bb9d438b84e73080ae9d251f199038a42c8d1f08e41ada0bb618f7fa0d82437c884934b9991a0f7d2f1005d1a2bb1ed63ad0439935a8cae127e29fb5e5b2c6893aaafafbef4e98d390c56b39419092fd838e4745e5a7fee5c738ab6d5a2acc8fef53306da96b1df395b46dbe56f04e2445a99dc1a58c7992f94dd033bdfb3404b6d6f8ced51696ea239eb7c17d2b183dad774a9354890528712d02d628458366422be09ef6eeba22ae5acaf37c9b8f0cef6fff2fcf0deea6fdccffa495b314c7877cf5bbd0caa16cf7de250d204')

key = b'7aeaef7351e88b7a'
iv  = b'b2195af3d80ec529'

cipher = AES.new(key, AES.MODE_CBC, iv)
pt = cipher.decrypt(ct)
try:
    pt = unpad(pt, 16)
except ValueError:
    pass

f = open('hg/00manifest.i', 'wb')
f.write(pt)
f.close()
