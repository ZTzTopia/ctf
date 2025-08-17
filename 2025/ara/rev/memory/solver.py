flag = "ARA6{"

v9 = 0
v10 = 0
v14 = 0
v15 = 0

v26 = 5
v27 = 0
v28 = 0

v33 = 0
v34 = 0

while ( 1 ):
    v15 = v28 + v27

    v9 = (v15 // 26) | ((v15 % 26) << 8)
    v10 = (v9 >> 8) & 0xFF

    v14 = v10 + 64
    v33 = v10 + 64
    v34 = v14

    if v28 == -1:
        break

    v28 = v28 + 1
    
    if v26 == -1:
        break

    v26 = v26 + 1

    if v28 == 15:
        if v27 == -1:
            break
        v27 = v27 + 1
        v28 = 0

    flag += chr(v14)
    if v27 == 4:
        if len(flag) == 66:
            break

print(flag + "}")
