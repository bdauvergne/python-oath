try:
    from functools import reduce
except ImportError:
    # not necesary in Python 2.x
    pass

def compare_digest(a, b):
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError
    if len(a) != len(b):
        return False
    return reduce(bool.__and__, map(lambda x: x[0] == x[1], zip(a, b)))

