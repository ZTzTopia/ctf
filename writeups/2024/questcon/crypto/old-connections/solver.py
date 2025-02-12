def vigenere_decrypt(ciphertext, key):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    decrypted_message = []
    
    key = (key * (len(ciphertext) // len(key) + 1))[:len(ciphertext)]
    
    for i in range(len(ciphertext)):
        cipher_index = alphabet.index(ciphertext[i])
        key_index = alphabet.index(key[i])

        decrypted_index = (cipher_index - key_index) % len(alphabet)
        decrypted_message.append(alphabet[decrypted_index])
    
    return ''.join(decrypted_message)

ciphertext = "UFJKXQZQUNB"
key = "SOLVECRYPTO"
decrypted_message = vigenere_decrypt(ciphertext, key)

print("Decrypted message:", decrypted_message)
