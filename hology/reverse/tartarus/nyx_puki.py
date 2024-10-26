import base64

def xor_decrypt(data, key, length):
    decrypted_data = bytearray()
    key_len = len(key)
    for i in range(len(data)):
        decrypted_data.append(data[i] ^ key[i % length])
    return decrypted_data

def decode_file(filepath, key1, key2):
    with open(filepath, "rb") as f:
        encrypted_data = f.read()

    base64_decoded_data = base64.b64decode(encrypted_data)
    base64_decoded_data = base64_decoded_data[:-13]

    decrypted_data = xor_decrypt(base64_decoded_data, key2.encode(), len(key1))

    base64_decrypted_data = base64.b64decode(decrypted_data)
    base64_decrypted_data = base64_decrypted_data[:-13]
    
    return xor_decrypt(base64_decrypted_data, key1.encode(), len(key1))

key1 = "ca^12asscxvnoiwpeqwejkxoisasdnajksndjkwnjnejbdojeboewiudbcijdonipwj90owpqo;ksd"
key2 = "sillymistake_312312390u3i12=89123900329i01\0nyx\0%s/%s\0\0\0\0ABCDEFGHIJKLMNOPQRSTUV"

decrypted_content = decode_file("flag.txt", key1, key2)
print(decrypted_content.decode())
