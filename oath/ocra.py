import hmac
import hashlib
import re
import hotp
import random
import string

'''
    Implementation of OCRA


    See also http://tools.ietf.org/html/draft-mraihi-mutual-oath-hotp-variants-14
'''

__ALL__ = ('str2ocrasuite')

def is_int(v):
    try:
        int(v)
        return True
    except ValueError:
        return False

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
            return hotp.dec(h, self.truncation_length)
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

    def __init__(self, C=None, Q=None, P=None, S=None, T=None):
        self.C = C
        self.Q = Q
        self.P = P
        self.S = S
        self.T = T

    def __call__(self, C=None, Q=None, P=None, P_digest=None, S=None, T=None,
            T_precomputed=None, Qsc=None):
        datainput = ''
        if self.C:
            try:
                C = int(C)
                if C < 0 or C > 2**64:
                    raise Exception()
            except:
                raise ValueError, ('Invalid counter value', C)
            datainput += hotp.int2beint64(int(C))
        if self.Q:
            max_length = self.Q[1]
            if Qsc is not None:
                # Mutual Challenge-Response
                Q = Qsc
                max_length *= 2
            if Q is None or not isinstance(Q, str) or len(Q) > max_length:
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
            if self.Q[0] == 'N':
                Q = hex(int(Q))[2:]
                Q += '0' * (len(Q) % 2)
                Q = Q.decode('hex')
            if self.Q[0] == 'A':
                pass
            if self.Q[0] == 'H':
                Q = Q.decode('hex')
            datainput += Q
            datainput += '\0' * (128-len(Q))
        if self.P:
            if P_digest:
                if len(P) == self.P.digest_size:
                    datainput += P_digest
                elif len(P) == 2*self.P.digest_size:
                    datainput += P_digest.decode('hex')
                else:
                    raise ValueError, ('Pin/Password digest invalid', P_digest)
            elif P is None:
                raise ValueError, 'Pin/Password missing'
            else:
                datainput += self.P(P).digest()
        if self.S:
            if S is None or len(S) != self.S:
                raise ValueError, 'session'
            datainput += S
        if self.T:
            if is_int(T_precomputed):
                datainput += hotp.int2beint64(int(T_precomputed))
            elif is_int(T):
                datainput += hotp.int2beint64(int(T / self.T))
            else:
                raise ValueError, 'timestamp'
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
    return DataInput(**datainputs)


class OcraSuite(object):
    def __init__(self, ocrasuite_description, crypto_function, data_input):
        self.ocrasuite_description = ocrasuite_description
        self.crypto_function = crypto_function
        self.data_input = data_input

    def __call__(self, key, **kwargs):
        data_input = self.ocrasuite_description + '\0' \
                + self.data_input(**kwargs)
        return self.crypto_function(key, data_input)

    def accept(self, response, key, **kwargs):
        return str(response) == self(key, **kwargs)

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
    return OcraSuite(ocrasuite_description, crypto_function, data_input)

class StateException(Exception):
    pass

DEFAULT_LENGTH = 20

class OCRAChallengeResponse(object):
    state = 1

    def __init__(self, key, ocrasuite_description):
        self.key = key
        self.ocrasuite = str2ocrasuite(ocrasuite_description)
        if not ocrasuite.data_input.Q:
            raise ValueError, ('Ocrasuite must have a Q descriptor',)

def compute_challenge(Q):
    kind, length = Q
    r = xrange(0, length)
    if kind == 'N':
        c = ''.join([random.choice(string.digits) for i in r])
    elif kind == 'A':
        alphabet = string.digits + string.letters
        c = ''.join([random.choice(alphabet) for i in r])
    elif kind == 'H':
        c = ''.join([random.choice(string.hexdigits) for i in r])
    else:
        raise ValueError, ('Q kind is unknown:', kind)
    return c

class OCRAChallengeResponseVerifier(OCRAChallengeResponse):
    SERVER_STATE_COMPUTE_CHALLENGE = 1
    SERVER_STATE_VERIFY_RESPONSE = 2
    SERVER_STATE_FINISHED = 3

    def compute_challenge(self):
        if self.state != self.SERVER_STATE_COMPUTE_CHALLENGE:
            raise StateException()
        self.challenge = compute_challenge(self.ocrasuite.data_input.Q)
        self.state = self.SERVER_STATE_VERIFY_RESPONSE
        return self.challenge

    def verify_response(self, response, **kwargs):
        if self.state != self.SERVER_STATE_VERIFY_RESPONSE:
            return StateException()
        c = self.ocrasuite(self.key, Q=self.challenge, **kwargs) == response
        if c:
            self.state = self.SERVER_STATE_FINISHED
        return c


class OCRAChallengeResponseClient(OCRAChallengeResponse):
    def compute_response(self, challenge, **kwargs):
        return self.ocrasuite(self.key, Q=self.challenge, **kwargs)

class OCRAMutualChallengeResponseClient(OCRAChallengeResponse):
    CLIENT_STATE_COMPUTE_CLIENT_CHALLENGE = 1
    CLIENT_STATE_VERIFY_SERVER_RESPONSE = 2
    CLIENT_STATE_COMPUTE_CLIENT_RESPONSE = 3
    CLIENT_STATE_FINISHED = 4

    def compute_client_challenge(self):
        if self.state != self.CLIENT_STATE_COMPUTE_CLIENT_CHALLENGE:
            raise StateException()
        self.client_challenge = compute_challenge(self.ocrasuite.data_input.Q)
        self.state = self.CLIENT_STATE_VERIFY_SERVER_RESPONSE
        return self.client_challenge

    def verify_server_response(self, response, challenge, **kwargs):
        if self.state != self.CLIENT_STATE_VERIFY_SERVER_RESPONSE:
            return StateException()
        self.server_challenge = challenge
        q = self.client_challenge+self.server_challenge
        c = self.ocrasuite(self.key, Qsc=q, **kwargs) == response
        if c:
            self.state = self.CLIENT_STATE_COMPUTE_CLIENT_RESPONSE
        return c

    def compute_client_response(self, **kwargs):
        if self.state != self.CLIENT_STATE_COMPUTE_CLIENT_RESPONSE:
            return StateException()
        q = self.server_challenge+self.client_challenge
        rc = self.ocrasuite(self.key, Qsc=q, **kwargs)
        self.state = self.CLIENT_STATE_FINISHED
        return rc

class OCRAMutualChallengeResponseServer(OCRAChallengeResponse):
    SERVER_STATE_COMPUTE_SERVER_RESPONSE = 1
    SERVER_STATE_VERIFY_CLIENT_RESPONSE = 2
    SERVER_STATE_FINISHED = 3

    def compute_server_response(self, challenge, **kwargs):
        if self.state != self.SERVER_STATE_COMPUTE_SERVER_RESPONSE:
            raise StateException()
        self.client_challenge = challenge
        self.server_challenge = compute_challenge(self.ocrasuite.data_input.Q)
        q = self.client_challenge+self.server_challenge
        # no need for pin with server mode
        kwargs.pop('P', None)
        kwargs.pop('P_digest', None)
        rs = self.ocrasuite(self.key, Qsc=q, **kwargs)
        self.state = self.SERVER_STATE_VERIFY_CLIENT_RESPONSE
        return rs, self.server_challenge

    def verify_client_response(self, response, **kwargs):
        if self.state != self.SERVER_STATE_VERIFY_CLIENT_RESPONSE:
            raise StateException()
        q = self.server_challenge+self.client_challenge
        c = self.ocrasuite(self.key, Qsc=q, **kwargs) == response
        if c:
            self.state = self.SERVER_STATE_FINISHED
        return c

if __name__ == '__main__':
    key20 = '3132333435363738393031323334353637383930'.decode('hex')
    key32 = '3132333435363738393031323334353637383930313233343536373839303132'\
            .decode('hex')
    key64 = '31323334353637383930313233343536373839303132333435363738393031323\
334353637383930313233343536373839303132333435363738393031323334'.decode('hex')
    pin = '1234'
    pin_sha1 = '7110eda4d09e062aa5e4a390b0a572ac0d2c0220'.decode('hex')
    tests = [ { 'ocrasuite': 'OCRA-1:HOTP-SHA1-6:QN08',
                'key': key20,
                'vectors': [
                    {'params': { 'Q': '00000000' }, 'result': '237653' },
                    {'params': { 'Q': '11111111' }, 'result': '243178' },
                    {'params': { 'Q': '22222222' }, 'result': '653583' },
                    {'params': { 'Q': '33333333' }, 'result': '740991' },
                    {'params': { 'Q': '44444444' }, 'result': '608993' },
                    {'params': { 'Q': '55555555' }, 'result': '388898' },
                    {'params': { 'Q': '66666666' }, 'result': '816933' },
                    {'params': { 'Q': '77777777' }, 'result': '224598' },
                    {'params': { 'Q': '88888888' }, 'result': '750600' },
                    {'params': { 'Q': '99999999' }, 'result': '294470' }
                ]
              },
              { 'ocrasuite': 'OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1',
                'key': key32,
                'vectors': [
                    {'params': { 'C': 0, 'Q': '12345678' }, 'result': '65347737' },
                    {'params': { 'C': 1, 'Q': '12345678' }, 'result': '86775851' },
                    {'params': { 'C': 2, 'Q': '12345678' }, 'result': '78192410' },
                    {'params': { 'C': 3, 'Q': '12345678' }, 'result': '71565254' },
                    {'params': { 'C': 4, 'Q': '12345678' }, 'result': '10104329' },
                    {'params': { 'C': 5, 'Q': '12345678' }, 'result': '65983500' },
                    {'params': { 'C': 6, 'Q': '12345678' }, 'result': '70069104' },
                    {'params': { 'C': 7, 'Q': '12345678' }, 'result': '91771096' },
                    {'params': { 'C': 8, 'Q': '12345678' }, 'result': '75011558' },
                    {'params': { 'C': 9, 'Q': '12345678' }, 'result': '08522129' }
                ]
              },
              { 'ocrasuite': 'OCRA-1:HOTP-SHA256-8:QN08-PSHA1',
                'key': key32,
                'vectors': [
                    {'params': { 'Q': '00000000' }, 'result': '83238735' },
                    {'params': { 'Q': '11111111' }, 'result': '01501458' },
                    {'params': { 'Q': '22222222' }, 'result': '17957585' },
                    {'params': { 'Q': '33333333' }, 'result': '86776967' },
                    {'params': { 'Q': '44444444' }, 'result': '86807031' }
                ]
              },
              { 'ocrasuite': 'OCRA-1:HOTP-SHA512-8:C-QN08',
                'key': key64,
                'vectors': [
                    {'params': { 'C': '00000', 'Q': '00000000' }, 'result': '07016083' },
                    {'params': { 'C': '00001', 'Q': '11111111' }, 'result': '63947962' },
                    {'params': { 'C': '00002', 'Q': '22222222' }, 'result': '70123924' },
                    {'params': { 'C': '00003', 'Q': '33333333' }, 'result': '25341727' },
                    {'params': { 'C': '00004', 'Q': '44444444' }, 'result': '33203315' },
                    {'params': { 'C': '00005', 'Q': '55555555' }, 'result': '34205738' },
                    {'params': { 'C': '00006', 'Q': '66666666' }, 'result': '44343969' },
                    {'params': { 'C': '00007', 'Q': '77777777' }, 'result': '51946085' },
                    {'params': { 'C': '00008', 'Q': '88888888' }, 'result': '20403879' },
                    {'params': { 'C': '00009', 'Q': '99999999' }, 'result': '31409299' }
                ]
              },
              { 'ocrasuite': 'OCRA-1:HOTP-SHA512-8:QN08-T1M',
                'key': key64,
                'vectors': [
                    {'params': { 'Q': '00000000', 'T_precomputed': int('132d0b6', 16) },
                        'result': '95209754' },
                    {'params': { 'Q': '11111111', 'T_precomputed': int('132d0b6', 16) },
                        'result': '55907591' },
                    {'params': { 'Q': '22222222', 'T_precomputed': int('132d0b6', 16) },
                        'result': '22048402' },
                    {'params': { 'Q': '33333333', 'T_precomputed': int('132d0b6', 16) },
                        'result': '24218844' },
                    {'params': { 'Q': '44444444', 'T_precomputed': int('132d0b6', 16) },
                        'result': '36209546' },
                ]
              },
            ]

    for test in tests:
        ocrasuite = str2ocrasuite(test['ocrasuite'])
        key = test['key']
        for vector in test['vectors']:
            params = vector['params']
            result = vector['result']
            if ocrasuite.data_input.P:
                params['P'] = pin
            assert ocrasuite(key, **params) == result

    mut_suite = 'OCRA-1:HOTP-SHA256-8:QA08'
    ocra_client = OCRAMutualChallengeResponseClient(key32, mut_suite)
    ocra_server = OCRAMutualChallengeResponseServer(key32, mut_suite)
    qc = ocra_client.compute_client_challenge()
    rs, qs = ocra_server.compute_server_response(qc)
    assert ocra_client.verify_server_response(rs, qs)
    rc = ocra_client.compute_client_response()
    assert ocra_server.verify_client_response(rc)
