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
    key_sha1 = binascii.hexlify('1234567890'*2)
    key_sha256 = binascii.hexlify('1234567890'*2+'12')
    key_sha512 = binascii.hexlify('1234567890'*6+'1234')
    # Test vector extracted from
    # http://tools.ietf.org/html/draft-mraihi-totp-timebased-08#appendix-B
    tv = '''|      59     |  1970-01-01  | 0000000000000001 | 94287082 |  SHA1  |
   |             |   00:00:59   |                  |          |        |
   |      59     |  1970-01-01  | 0000000000000001 | 46119246 | SHA256 |
   |             |   00:00:59   |                  |          |        |
   |      59     |  1970-01-01  | 0000000000000001 | 90693936 | SHA512 |
   |             |   00:00:59   |                  |          |        |
   |  1111111109 |  2005-03-18  | 00000000023523EC | 07081804 |  SHA1  |
   |             |   01:58:29   |                  |          |        |
   |  1111111109 |  2005-03-18  | 00000000023523EC | 68084774 | SHA256 |
   |             |   01:58:29   |                  |          |        |
   |  1111111109 |  2005-03-18  | 00000000023523EC | 25091201 | SHA512 |
   |             |   01:58:29   |                  |          |        |
   |  1111111111 |  2005-03-18  | 00000000023523ED | 14050471 |  SHA1  |
   |             |   01:58:31   |                  |          |        |
   |  1111111111 |  2005-03-18  | 00000000023523ED | 67062674 | SHA256 |
   |             |   01:58:31   |                  |          |        |
   |  1111111111 |  2005-03-18  | 00000000023523ED | 99943326 | SHA512 |
   |             |   01:58:31   |                  |          |        |
   |  1234567890 |  2009-02-13  | 000000000273EF07 | 89005924 |  SHA1  |
   |             |   23:31:30   |                  |          |        |
   |  1234567890 |  2009-02-13  | 000000000273EF07 | 91819424 | SHA256 |
   |             |   23:31:30   |                  |          |        |
   |  1234567890 |  2009-02-13  | 000000000273EF07 | 93441116 | SHA512 |
   |             |   23:31:30   |                  |          |        |
   |  2000000000 |  2033-05-18  | 0000000003F940AA | 69279037 |  SHA1  |
   |             |   03:33:20   |                  |          |        |
   |  2000000000 |  2033-05-18  | 0000000003F940AA | 90698825 | SHA256 |
   |             |   03:33:20   |                  |          |        |
   |  2000000000 |  2033-05-18  | 0000000003F940AA | 38618901 | SHA512 |
   |             |   03:33:20   |                  |          |        |
   | 20000000000 |  2603-10-11  | 0000000027BC86AA | 65353130 |  SHA1  |
   |             |   11:33:20   |                  |          |        |
   | 20000000000 |  2603-10-11  | 0000000027BC86AA | 77737706 | SHA256 |
   |             |   11:33:20   |                  |          |        |
   | 20000000000 |  2603-10-11  | 0000000027BC86AA | 47863826 | SHA512 |
   |             |   11:33:20   |                  |          |        |'''
    test_vectors  = [ [ cell.strip() for cell in line.strip(' |').split('|') ] for line in tv.splitlines()]
    test_vectors  = [ line for line in test_vectors if line[0] and len(line) > 3 ]
    hash_algos = {
            'SHA1': {
                'key': key_sha1,
                'alg': hashlib.sha1, },
            'SHA256': {
                'key': key_sha256,
                'alg': hashlib.sha256, },
            'SHA512': {
                'key': key_sha512,
                'alg': hashlib.sha512, },
    }
    for t, _, _, response, algo_key in test_vectors:
        assert accept_totp(hash_algos[algo_key]['key'], response, t=int(t),
                hash=hash_algos[algo_key]['alg'])


#    test_vectors = [
#            (key_sha1, 59, '94287082', hashlib.sha1),
#            (key_sha256, 59, '46119246', hashlib.sha256),
#            (key_sha512, 59, '90693936', hashlib.sha512),
#            (key_sha1, 1111111109, '07081804', hashlib.sha1),
#            (key_sha256, 1111111109, '68084774', hashlib.sha256),
#            (key_sha512, 1111111109, '25091201', hashlib.sha512),
#            (key_sha1, 1111111111, '14050471', hashlib.sha1),
#            (key_sha256, 1111111111, '67062674', hashlib.sha256),
#            (key_sha512, 1111111111, '99943326', hashlib.sha512),
#            (key_sha1, 1234567890, '', hashlib.sha1),
#            (key_sha256, 1234567890, '', hashlib.sha256),
#            (key_sha512, 1234567890, '', hashlib.sha512),
#    for key, t, response, hash in test_vectors:
#        assert accept_totp(key, response, t=t, hash=hash)
#
#    import sys
#    if len(sys.argv) > 1:
#        print totp(sys.argv[1], format='dec6')
