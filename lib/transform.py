def cae(buf, key):
    return bytearray([ ((_-key) & 0xFF) for _ in buf])

def xor(buf, key):
    return bytearray([ ((buf[i]^ord(key[i % len(key)])) & 0xFF) for i in range(len(buf)) ])

def b64(buf, key):
    for _ in range(key):
        buf = base64.b64decode(buf)
    return buf
