import time
import hashlib
import datetime
import calendar

from hotp import hotp

def totp(key, format='dec8', period=30, t=None, hash=hashlib.sha1):
    '''Compute a TOTP value as prescribed by OATH specifications.

       See http://tools.ietf.org/html/draft-mraihi-totp-timebased-06
    '''
    if t is None:
        t = time.time()
    else:
        if isinstance(t, datetime.datetime):
            t = calendar.timegm(t.utctimetuple())
        else:
            t = int(t)
    T = int(t/period)
    return hotp(key, T, format=format, hash=hash)

def accept_totp(key, response, period=30, format='dec8', hash=hashlib.sha1,
        forward_drift=1, backward_drift=1, drift=0, t=None):
    '''Validate a TOTP value inside a window of 
       [drift-bacward_drift:drift+forward_drift] of time steps.
       Where drift is the drift obtained during the last call to accept_totp.

       Return a pair (v,d) where v is a boolean giving the result, and d the
       needed drift to validate the value. The drift value should be saved for
       user with later call to accept_totp in order to accept a slowly
       accumulating drift with a token clock.
    '''
    t = t or time.time()
    for i in range(-backward_drift,forward_drift+1):
        d = (drift+i) * period
        if totp(key, format=format, period=period, hash=hash, t=t+d) == response:
            return True, drift+i
    return False, 0


if __name__ == '__main__':
    import binascii
    # Test vectors extracted from RFC 4226
    secret = binascii.hexlify('12345678901234567890')
    tvector3 = [
            (59, hashlib.sha1, '94287082'),
            (1111111109, hashlib.sha1, '07081804') ]
    for timestamp, hash, value in tvector3:
        assert (totp(secret,t=datetime.datetime.utcfromtimestamp(timestamp),hash=hash) == value)
    assert(accept_totp(secret, '94287082', t=65) == (True, -1))
    assert(accept_totp(secret, '94287082', t=65, drift=-1) == (True, -1))
    import sys
    if len(sys.argv) > 1:
        print totp(sys.argv[1], format='dec6')
