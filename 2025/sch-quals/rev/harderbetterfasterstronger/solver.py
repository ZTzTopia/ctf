def decrypt_from_hex(hex_string):
    data = bytes.fromhex(hex_string)
    key0 = 0x25
    v12 = 0
    out = bytearray()

    for i, b in enumerate(data):
        v14 = v12 ^ (((3 * key0 + 5) << 2) & 0xFF | ((3 * key0 + 5) >> 6))
        v12 = (v12 + 13) & 0xFF
        out.append(b ^ ((v14 - (i & 0xF)) & 0xFF) ^ 6)

    return bytes(out)

print(decrypt_from_hex("849e87c7d2f6c8edc0f3102c2f05376d58674844b0d2908782fb09f3c1f83d46280e0a78604c604bbbdc869892d23ee4e6ec0036123103607a"))
