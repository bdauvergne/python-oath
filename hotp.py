import hashlib
import hmac
import binascii
import time
import datetime
import calendar

'''
Python implementation of HOTP and TOTP algorithms from the OATH project.

Copyright 2010, Benjamin Dauvergne

* All rights reserved.
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:

     * Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.'''

def __truncated_value(h):
    bytes = map(ord, h)
    offset = bytes[19] & 0xf
    v = (bytes[offset] & 0x7f) << 24 | (bytes[offset+1] & 0xff) << 16 | \
            (bytes[offset+2] & 0xff) << 8 | (bytes[offset+3] & 0xff)
    return v

def dec(h,p):
    v = str(__truncated_value(h))
    return v[len(v)-p:]

def __hotp(key, counter, hash=hashlib.sha1):
    hex_counter = hex(long(counter))[2:-1]
    hex_counter = '0' * (16 - len(hex_counter)) + hex_counter
    bin_counter = binascii.unhexlify(hex_counter)
    bin_key = binascii.unhexlify(key)

    return hmac.new(bin_key, bin_counter, hash).digest()

def hotp(key,counter,format='dec6',hash=hashlib.sha1):
    '''Compute a HOTP value as prescribed by RFC4226
    
       See http://tools.ietf.org/html/rfc4226
    '''
    bin_hotp = __hotp(key, counter, hash)

    if format == 'hex40':
        return binascii.hexlify(bin_hotp[0:5])
    elif format == 'dec6':
        return dec(bin_hotp, 6)
    elif format == 'dec7':
        return dec(bin_hotp, 7)
    elif format == 'dec8':
        return dec(bin_hotp, 8)
    else:
        raise ValueError('unknown format')

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
    # Test vectors extracted from RFC 4226
    secret = '3132333435363738393031323334353637383930'
    tvector = [
        (0, 'cc93cf18508d94934c64b65d8ba7667fb7cde4b0'),
        (1, '75a48a19d4cbe100644e8ac1397eea747a2d33ab'),
        (2, '0bacb7fa082fef30782211938bc1c5e70416ff44'),
        (3, '66c28227d03a2d5529262ff016a1e6ef76557ece'),
        (4, 'a904c900a64b35909874b33e61c5938a8e15ed1c'),
        (5, 'a37e783d7b7233c083d4f62926c7a25f238d0316'),
        (6, 'bc9cd28561042c83f219324d3c607256c03272ae'),
        (7, 'a4fb960c0bc06e1eabb804e5b397cdc4b45596fa'),
        (8, '1b3c89f65e6c9e883012052823443f048b4332db'),
        (9, '1637409809a679dc698207310c8c7fc07290d9e5'), ]
    for counter, value in tvector:
        assert(binascii.hexlify(__hotp(secret, counter)) == value)
    tvector2 = [
        (0, '4c93cf18', '1284755224', '755224',),
        (1, '41397eea', '1094287082', '287082',),
        (2, '82fef30',  '137359152',  '359152',),
        (3, '66ef7655', '1726969429', '969429',),
        (4, '61c5938a', '1640338314', '338314',),
        (5, '33c083d4', '868254676',  '254676',),
        (6, '7256c032', '1918287922', '287922',),
        (7, '4e5b397',  '82162583',   '162583',),
        (8, '2823443f', '673399871',  '399871',),
        (9, '2679dc69',  '645520489', '520489',),]
    for counter, hexa, deci, trunc in tvector2:
        h = __hotp(secret, counter)
        v = __truncated_value(h)
        assert(hex(v)[2:] == hexa)
        assert(str(v) == deci)
        assert(dec(h,6) == trunc)
    secret = binascii.hexlify('12345678901234567890')
    tvector3 = [
            (59, hashlib.sha1, '94287082'),
            (1111111109, hashlib.sha1, '07081804') ]
    for timestamp, hash, value in tvector3:
        assert (totp(secret,t=datetime.datetime.utcfromtimestamp(timestamp),hash=hash) == value)
    assert(accept_totp(secret, '94287082', t=65) == (True, -1))
    assert(accept_totp(secret, '94287082', t=65, drift=-1) == (True, -1))
