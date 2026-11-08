def fromhex(s):
    return bytes.fromhex(s)


def tohex(_bytes):
    return _bytes.hex()


def tobytes(b_or_s):
    if isinstance(b_or_s, bytes):
        return b_or_s
    return b_or_s.encode("utf8")
