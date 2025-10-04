ops = [ 'j3s5l', 'j3s5l', 'm9kp2', 'qwx7z', 'qwx7z', 'm9kp2', 'j3s5l', 'j3s5l', 'qwx7z', 'j3s5l', 'j3s5l', 'qwx7z', 'm9kp2', 'j3s5l', 'qwx7z', 'j3s5l', 'm9kp2', 'j3s5l', 'j3s5l', 'm9kp2', 'm9kp2', 'qwx7z', 'j3s5l', 'm9kp2', 'j3s5l', 'm9kp2', 'm9kp2', 'j3s5l', 'm9kp2', 'qwx7z', 'qwx7z', 'qwx7z', 'qwx7z' ]
k = [ 143, 193, 38, 93, 97, 13, 149, 22, 102, 163, 38, 84, 55, 157, 130, 12, 65, 133, 194, 3, 9, 162, 198, 41, 77, 20, 55, 76, 17, 192, 207, 104, 163 ]
ct = [ 200, 132, 39, 158, 180, 71, 220, 93, 151, 155, 93, 185, 67, 194, 245, 111, 49, 236, 178, 113, 96, 272, 161, 54, 33, 77, 55, 43, 100, 289, 310, 205, 288 ]

out = []
for o, ki, ci in zip(ops, k, ct): 
    out.append(chr(ci - ki if o == 'qwx7z' else ci + ki if o == 'm9kp2' else ci ^ ki))

print(''.join(out))
