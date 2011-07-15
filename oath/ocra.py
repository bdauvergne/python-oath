import hmac
import hashlib
import re
import binascii
import hotp

'''
    Implementation of OCRA


    See also http://tools.ietf.org/html/draft-mraihi-mutual-oath-hotp-variants-14
'''

__ALL__ = ('str2ocrasuite')

# Constants
PERIODS = { 'H': 3600, 'M': 60, 'S': 1 }
HOTP = 'HOTP'
OCRA_1 = 'OCRA-1'

class CryptoFunction(object):
    '''Represents an OCRA CryptoFunction specification'''
    def __init__(self, hash_algo, truncation_length):
        self.hash_algo = hash_algo
        self.truncation_length = truncation_length

    def __call__(self, key, data_input):
        h = hmac.new(key, data_input, self.hash_algo).digest()
        if self.truncation_length:
            return str(hotp.truncated_value(h))[-self.truncation_length:]
        else:
            return str(hotp.truncated_value(h))

    def __str__(self):
        return 'HOTP-%s-%s' % (self.hash_algo.__name__, self.truncation_length)

def str2hashalgo(description):
    algo = getattr(hashlib, description.lower(), None)
    if not callable(algo):
        raise ValueError, ('Unknown hash algorithm', s[1])
    return algo

def str2cryptofunction(crypto_function_description):
    '''
       Convert an OCRA crypto function description into a CryptoFunction
       instance
    '''
    s = crypto_function_description.split('-')
    if len(s) != 3:
        raise ValueError, 'CryptoFunction description must be triplet separated by -'
    if s[0] != HOTP:
        raise ValueError, ('Unknown CryptoFunction kind', s[0])
    algo = str2hashalgo(s[1])
    try:
        truncation_length = int(s[2])
        if truncation_length < 0 or truncation_length > 10:
            raise ValueError
    except ValueError:
        raise ValueError, ('Invalid truncation length', s[2])
    return CryptoFunction(algo, truncation_length)

class DataInput:
    '''
       OCRA data input description

       By calling this instance of this class and giving the needed parameter
       corrresponding to the data input description, it compute a binary string
       to give to the HMAC algorithme implemented by a CryptoFunction object
    '''

    __slots__ = [ 'ocrasuite', 'C', 'Q', 'P', 'S', 'T' ]

    def __init__(self, ocrasuite, C=None, Q=None, P=None, S=None, T=None):
        self.ocrasuite = ocrasuite
        self.C = C
        self.Q = Q
        self.P = P
        self.S = S
        self.T = T

    def __call__(self, C=None, Q=None, P=None, S=None, T=None):
        datainput = self.ocrasuite + '\0'
        if self.C:
            if C is None or not isinstance(C, int) or C < 0 or C > 2**64:
                raise ValueError, ('Invalid counter value', C)
            datainput += hotp.int2beint64(C)
        if self.Q:
            if Q is None or not isinstance(Q, str) or len(Q) > self.Q[1]:
                raise ValueError, 'challenge'
            if self.Q[0] == 'N' and not Q.isdigit():
                raise ValueError, 'challenge'
            if self.Q[0] == 'A' and not Q.isalnum():
                raise ValueError, 'challenge'
            if self.Q[0] == 'H':
                try:
                    int(Q, 16)
                except ValueError:
                    raise ValueError, 'challenge'
            datainput += Q
            datainput += '0' * (128-len(Q))
        if self.P:
            if P is None:
                raise ValueError, 'Pin/Password'
            datainput += self.P(P).digest()
        if self.S:
            if S is None or len(S) != self.S:
                raise ValueError, 'session'
            datainput += S
        if self.T:
            if not isinstance(T, int):
                raise ValueError, 'timestamp'
            datainput += hotp.int2beint64(int(T / self.T))
        return datainput

    def __str__(self):
        return self.ocrasuite

def str2datainput(datainput_description):
    elements = datainput_description.split('-')
    datainputs = {}
    for element in elements:
        letter = element[0]
        if letter in datainputs:
            raise ValueError, ('DataInput alreadu present %s', element, datainput_description)
        if letter == 'C':
            datainputs['C'] = 1
        elif letter == 'Q':
            if len(element) == 1:
                datainputs['Q'] = ('N',8)
            else:
                second_letter = element[1]
                try:
                    if second_letter not in 'ANH':
                        raise ValueError
                    length = int(element[2:])
                    if length < 4 or length > 64:
                        raise ValueError
                except ValueError:
                    raise ValueError, ('Invalid challenge descriptor', element)
                datainputs['Q'] = (second_letter, length)
        elif letter == 'P':
            algo = str2hashalgo(element[1:] or 'SHA1')
            datainputs['P'] = algo
        elif letter == 'S':
            length = 64
            if element[1:]:
                try:
                    length = int(element[1:])
                except ValueError:
                    raise ValueError, ('Invalid session data descriptor', element)
            datainputs['S'] = length
        elif letter == 'T':
            complement = element[1:] or '1M'
            try:
                length = 0
                if not re.match('^(\d+[HMS])+$', complement):
                    raise ValueError
                parts = re.findall('\d+[HMS]', complement)
                for part in parts:
                    period = part[-1]
                    quantity = int(part[:-1])
                    length += quantity * PERIODS[period]
                datainputs['T'] = length
            except ValueError:
                raise ValueError, ('Invalid timestamp descriptor', element)
        else:
            raise ValueError, ('Invalid datainput descriptor', element)
    return DataInput(datainput_description, **datainputs)


class OcraSuite(object):
    def __init__(self, crypto_function, data_input):
        self.crypto_function = crypto_function
        self.data_input = data_input

    def __call__(self, key, **kwargs):
        return self.crypto_function(key, self.data_input(**kwargs))

    def accept(self, response, key, **kwargs):
        return response == self(key, **kwargs)

    def __str__(self):
        return '<OcraSuite crypto_function:%s data_input:%s>' % (self.crypto_function,
                self.data_input)

def str2ocrasuite(ocrasuite_description):
    elements = ocrasuite_description.split(':')
    if len(elements) != 3:
        raise ValueError, ('Bad OcraSuite description', ocrasuite_description)
    if elements[0] != OCRA_1:
        raise ValueError, ('Unsupported OCRA identifier', elements[0])
    crypto_function = str2cryptofunction(elements[1])
    data_input = str2datainput(elements[2])
    return OcraSuite(crypto_function, data_input)

if __name__ == '__main__':
    assert str2cryptofunction('HOTP-SHA256-6')
    ocrasuite = str2ocrasuite('OCRA-1:HOTP-SHA256-6:C-QN08-PSHA1-S1-T')
    print ocrasuite
    print ocrasuite('coin', C=1, Q='123', P='324324', S='x', T=123)
