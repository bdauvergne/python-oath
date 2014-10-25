from functools import reduce
def compare_digest(a, b):
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError
    if len(a) != len(b):
        return False
    return reduce(bool.__and__, [x[0] == x[1] for x in zip(a, b)])

