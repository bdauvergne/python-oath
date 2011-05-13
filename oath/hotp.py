import hashlib
import hmac
import binascii

'''
Python implementation of HOTP and TOTP algorithms from the OATH project.
'''

def __truncated_value(h):
    bytes = map(ord, h)
    offset = bytes[-1] & 0xf
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
    elif format == 'dec4':
        return dec(bin_hotp, 4)
    elif format == 'dec6':
        return dec(bin_hotp, 6)
    elif format == 'dec7':
        return dec(bin_hotp, 7)
    elif format == 'dec8':
        return dec(bin_hotp, 8)
    else:
        raise ValueError('unknown format')

def accept_hotp(key, response, counter, format='dec6', hash=hashlib.sha1,
        drift=3, backward_drift=0):
    '''
        Validate an HOTP value inside a window of
        [counter-backward_drift:counter+forward_drift]

        :params key:
            the shared secret
        :type key:
            hexadecimal string of even length
        :params response:
            the OTP to check
        :type response:
            ASCII string
        :params counter:
            value of the counter running inside an HOTP token, usually it is
            just the count of HOTP value accepte so far for a given shared
            secret
        :params format:
            the format of the HOTP hash to generate
        :params hash:
            the hashing algorithm to use, default to SHA1
        :params drift:
            how far we can look forward from the current value of the counter
        :params backward_drift:
            how far we can look backward from the current counter value to
            match the response, default to zero as it is usually a bad idea to
            look backward as the counter is only advanced when a valid value is
            checked (and so the counter on the token side should have been
            incremented too)

        :returns:
            a pair of a boolean and an integer:
             - first is True if the response is validated and False otherwise,
             - second is the new value for the counter; it can be more than
               counter + 1 if the drift window was used; you must store it if
               the response was validated.

        >>> accept_hotp('343434', '122323', 2, format='dec6')
            (False, 2)

        >>> hotp('343434', 2, format='dec6')
            '791903'

        >>> accept_hotp('343434', '791903', 2, format='dec6')
            (True, 3)

        >>> hotp('343434', 3, format='dec6')
            '907279'

        >>> accept_hotp('343434', '907279', 2, format='dec6')
            (True, 4)
    '''

    for i in range(-backward_drift, drift+1):
        if hotp(key, counter+i, format=format, hash=hash) == response:
            return True, counter+i+1
    return False,counter

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
        assert accept_hotp(secret, trunc, counter)
