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
    if not hasattr(bytes, 'fromhex'):  # Python 2
        if isinstance(a, unicode):
            a = a.decode('ascii')
        if isinstance(b, unicode):
            a = a.decode('ascii')
    if type(a) != type(b):
        raise TypeError('compared digest must be of the same type')
    if hasattr(bytes, 'fromhex'):  # Python 3
        if not isinstance(a, (bytes, str)):
            raise TypeError('digest must be bytes or str')
    else:  # Python 2
        if not isinstance(a, (str, unicode)):
            raise TypeError('digest must be str or unicode')
    if len(a) != len(b):
        return False
    return all(map(lambda x: x[0] == x[1], zip(a, b)))
