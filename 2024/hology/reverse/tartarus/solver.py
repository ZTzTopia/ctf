import base64

def decrypt(data, key, length):
    decoded_data = base64.b64decode(data)
    decoded_data = decoded_data[:-13] # Remove the "waifuku_ada_5" string

    decrypted_data = bytearray()
    for i in range(len(decoded_data)):
        decrypted_data.append(decoded_data[i] ^ ord(key[i % length]))
    return decrypted_data

def decode_file(filepath, key1, key2):
    with open(filepath, "rb") as f:
        encrypted_data = f.read()

    decrypted_data = decrypt(encrypted_data, key2, len(key1))
    decrypted_data = decrypt(decrypted_data, key1, len(key1))
    return decrypted_data

key1 = "ca^12asscxvnoiwpeqwejkxoisasdnajksndjkwnjnejbdojeboewiudbcijdonipwj90owpqo;ksd"
key2 = "sillymistake_312312390u3i12=89123900329i01\0nyx\0%s/%s\0\0\0\0ABCDEFGHIJKLMNOPQRSTUV"

decrypted_content = decode_file("flag.txt", key1, key2)
print(decrypted_content.decode().strip())
