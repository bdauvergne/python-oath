try:
    from functools import reduce
except ImportError:
    # not necesary in Python 2.x
    pass

if hasattr(bytes, 'fromhex'):
    # Python 3.x
    import binascii
    def fromhex(s):
        return bytes.fromhex(s)
    def tohex(bin):
        return binascii.hexlify(bin).decode('ascii')
else:
    # Python 2.x
    def fromhex(s):
        return s.decode('hex')
    def tohex(bin):
        return bin.encode('hex')

def tobytes(b_or_s):
    try:
        if isinstance(b_or_s, bytes):
            return b_or_s
    except NameError:
        if isinstance(b_or_s, str):
            return b_or_s
    return b_or_s.encode('utf8')

def compare_digest(a, b):
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError
    if len(a) != len(b):
        return False
    return reduce(bool.__and__, map(lambda x: x[0] == x[1], zip(a, b)))

