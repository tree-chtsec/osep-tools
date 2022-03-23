import hashlib, binascii

def convert(s):
    _hash = hashlib.new('md4', s.encode('utf-16le')).digest()
    return binascii.hexlify(_hash).decode()

if __name__ == '__main__':
    import sys
    convert(sys.stdin.read())
