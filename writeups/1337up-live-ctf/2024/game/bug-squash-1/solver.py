from Crypto.Cipher import AES

def get_iv():
    iv = bytearray([
        9, 59, 202, 213, 13, 62, 108, 125, 224, 15,
        10, 159, 13, 51, 70, 1
    ])
    
    b = 66
    for i in range(len(iv)):
        iv[i] ^= b

    return bytes(iv)

def decrypt_aes_ccb(ciphertext, key):
    iv = get_iv()
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.decrypt(ciphertext)

key = open('./Bug Hunting_Data/StreamingAssets/MeshText/win.key', 'rb').read()
ciphertext = open('./Bug Hunting_Data/StreamingAssets/MeshText/win.enc', 'rb').read()

image = decrypt_aes_ccb(ciphertext, key)
open('flag.png', 'wb').write(image)
