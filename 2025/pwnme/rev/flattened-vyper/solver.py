import base58

flag = ''

# Data
a = 0x9c1a44f72090b2084eff4360bf11986150f7b5b16b3d4c0a999ed8953cfd668a + 0x61ec705ea65e9bbf5b5a26cc5fa4f55ad1074377dce1ffbc52d65a8816af56a4
a -= 0xadaf670881744dc7aa596a2d1eb68dbc21fef929481f4bc6ec75331d53acbd2e
a %= (2**256) # Stay in 256-bit
print(hex(a))
data = bytes.fromhex(hex(a)[2:])
data = data.replace(b'\x00', b'')
flag += data.decode()

# Data
b = 0x81385805084428d13c1994377979238f1c9f574353e344bf9674b56f2380894f - 0x11fea6990cda43a993f3c8cb366da2c23305d78b65ad90ea8578bc704a1b5361
b ^= 0xcd1941de2602e740c239ec7184cd0608b8cebb856e7243bca25b386695fc5d4f
b ^= 0x4535f7c4dddcbd2e353778b864f7e5aadeb48786211942f0066b5715f41e1344
b += 0x9de848aa2e1f7fadbc76fdeb1e6d86e23f62c033260728029884a9e1533cf090
b += 0xc86afc4c1f60387b16cce4e4b7c47baf30b9fc18389a2563b2afbe90f43b938b
b %= (2**256) # Stay in 256-bit
print(hex(b))
data = bytes.fromhex(hex(b)[2:])
data = data.replace(b'\x00', b'')
flag += base58.b58decode(data).decode()

# Data
c = 0x8a7d2dab1437a704175dec5cd4ac755fa35b553d62798afc45e5bd1d30be723e ^ 0x493267cb0f8113a9bd75b52869d3344723cd0d18ac091431f0c8c0557d4d69c3
c -= 0xa3f4105dff5270ad5b285974bd7f411880965825ce709ecdb52d7d484df31bfd
c %= (2**256) # Stay in 256-bit
print(hex(c))
c ^= b
c %= (2**256) # Stay in 256-bit
print(hex(c))
data = bytes.fromhex(hex(c)[2:])
data = data.replace(b'\x00', b'')
flag += data.decode()

print(f'Flag: {flag}')
