try:
    from functools import reduce
except ImportError:
    # not necesary in Python 2.x
    pass

if hasattr(bytes, 'fromhex'):
    # Python 3.x
    def fromhex(s):
        return bytes.fromhex(s)
else:
    # Python 2.x
    def fromhex(s):
        return s.decode('hex')

def compare_digest(a, b):
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError
    if len(a) != len(b):
        return False
    return reduce(bool.__and__, map(lambda x: x[0] == x[1], zip(a, b)))

