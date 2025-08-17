dword_404094 = 10   # The Caesar cipher shift value
dword_404090 = 53   # The XOR key

transformed_password = 'cLVQjFMjcFDGQ'
password = ''

for char in transformed_password:
    char = chr(ord(char) ^ dword_404090)

    if char.isupper():
        char = chr(((ord(char) - 65 - dword_404094) % 26) + 65)
    elif char.islower():
        char = chr(((ord(char) - 97 - dword_404094) % 26) + 97)
    
    password += char

print(password)
