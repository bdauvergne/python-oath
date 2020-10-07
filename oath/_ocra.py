import hmac
import hashlib
import re
import random
import string

from . import _hotp as hotp, _utils

'''
    Implementation of OCRA


    See also http://tools.ietf.org/html/draft-mraihi-mutual-oath-hotp-variants-14
'''

__all__ = (
    'str2ocrasuite',
    'StateException',
    'OCRAChallengeResponseServer',
    'OCRAChallengeResponseClient',
    'OCRAMutualChallengeResponseServer',
    'OCRAMutualChallengeResponseClient',
)


def is_int(v):
    try:
        int(v)
        return True
    except ValueError:
        return False


# Constants
PERIODS = {'H': 3600, 'M': 60, 'S': 1}
HOTP = 'HOTP'
OCRA_1 = 'OCRA-1'


class CryptoFunction(object):
    '''Represents an OCRA CryptoFunction specification.

       :attribute hash_algo:
           an object implementing the digest interface as given by PEP 247 and
           the hashlib package
       :attribute truncation_length:
           the length to truncate the decimal representation, can be None, in
           this case no truncation is done.
    '''

    def __init__(self, hash_algo, truncation_length):
        assert hash_algo
        assert is_int(truncation_length) or truncation_length is None
        self.hash_algo = hash_algo
        self.truncation_length = truncation_length

    def __call__(self, key, data_input):
        '''Compute an HOTP digest using the given key and data input and
           following the current crypto function description.

           :param key:
               a byte string containing the HMAC key

           :param data_input:
               the data input assembled as a byte-string as described by the
               OCRA specification
           :returns:
               the computed digest
           :rtype: str
        '''
        h = hmac.new(key, data_input, self.hash_algo).digest()
        if self.truncation_length:
            return hotp.dec(h, self.truncation_length)
        else:
            return str(hotp.truncated_value(h))

    def __str__(self):
        '''Return the standard representation for the given crypto function.
        '''
        return 'HOTP-%s-%s' % (self.hash_algo.__name__, self.truncation_length)


def str2hashalgo(description):
    '''Convert the name of a hash algorithm as described in the OATH
       specifications, to a python object handling the digest algorithm
       interface, PEP-xxx.

       :param description
           the name of the hash algorithm, example
       :rtype: a hash algorithm class constructor
    '''
    algo = getattr(hashlib, description.lower(), None)
    if not callable(algo):
        raise ValueError('Unknown hash algorithm %s' % description)
    return algo


def str2cryptofunction(crypto_function_description):
    '''
       Convert an OCRA crypto function description into a CryptoFunction
       instance

       :param crypto_function_description:
       :returns:
           the CryptoFunction object
       :rtype: CryptoFunction
    '''
    s = crypto_function_description.split('-')
    if len(s) != 3:
        raise ValueError('CryptoFunction description must be triplet separated by -')
    if s[0] != HOTP:
        raise ValueError('Unknown CryptoFunction kind %s' % s[0])
    algo = str2hashalgo(s[1])
    try:
        truncation_length = int(s[2])
        if truncation_length < 0 or truncation_length > 10:
            raise ValueError()
    except ValueError:
        raise ValueError('Invalid truncation length %s' % s[2])
    return CryptoFunction(algo, truncation_length)


class DataInput(object):
    '''
       OCRA data input description

       By calling this instance of this class and giving the needed parameter
       corrresponding to the data input description, it compute a binary string
       to give to the HMAC algorithme implemented by a CryptoFunction object
    '''

    __slots__ = ['C', 'Q', 'P', 'S', 'T']

    def __init__(self, C=None, Q=None, P=None, S=None, T=None):
        self.C = C
        self.Q = Q
        self.P = P
        self.S = S
        self.T = T

    def __call__(self, C=None, Q=None, P=None, P_digest=None, S=None, T=None, T_precomputed=None, Qsc=None):
        datainput = b''
        if self.C:
            try:
                C = int(C)
                if C < 0 or C > 2 ** 64:
                    raise Exception()
            except:
                raise ValueError('Invalid counter value %s' % C)
            datainput += hotp.int2beint64(int(C))
        if self.Q:
            max_length = self.Q[1]
            if Qsc is not None:
                # Mutual Challenge-Response
                Q = Qsc
                max_length *= 2
            if Q is None or not isinstance(Q, str) or len(Q) > max_length:
                raise ValueError('challenge')
            if self.Q[0] == 'N' and not Q.isdigit():
                raise ValueError('challenge')
            if self.Q[0] == 'A' and not Q.isalnum():
                raise ValueError('challenge')
            if self.Q[0] == 'H':
                try:
                    int(Q, 16)
                except ValueError:
                    raise ValueError('challenge')
            if self.Q[0] == 'N':
                Q = '%x' % int(Q)
                Q += '0' * (len(Q) % 2)
                Q = _utils.fromhex(Q)
            if self.Q[0] == 'A':
                pass
            if self.Q[0] == 'H':
                Q = _utils.fromhex(Q)
            datainput += _utils.tobytes(Q)
            datainput += _utils.tobytes('\0' * (128 - len(Q)))
        if self.P:
            if P_digest:
                if len(P_digest) == self.P.digest_size:
                    datainput += _utils.tobytes(P_digest)
                elif len(P_digest) == 2 * self.P.digest_size:
                    datainput += _utils.fromhex(_utils.tobytes(P_digest))
                else:
                    raise ValueError('Pin/Password digest invalid %r' % P_digest)
            elif P is None:
                raise ValueError('Pin/Password missing')
            else:
                datainput += self.P(_utils.tobytes(P)).digest()
        if self.S:
            if S is None or len(S) != self.S:
                raise ValueError('session')
            datainput += _utils.tobytes(S)
        if self.T:
            if is_int(T_precomputed):
                datainput += hotp.int2beint64(int(T_precomputed))
            elif is_int(T):
                datainput += hotp.int2beint64(int(T / self.T))
            else:
                raise ValueError('timestamp')
        return datainput

    def __str__(self):
        values = []
        for slot in DataInput.__slots__:
            value = getattr(self, slot, None)
            if value is not None:
                values.append('{0}={1}'.format(slot, value))
        return '<{0} {1}>'.format(DataInput.__class__.__name__, ', '.join(values))


def str2datainput(datainput_description):
    elements = datainput_description.split('-')
    datainputs = {}
    for element in elements:
        letter = element[0]
        if letter in datainputs:
            raise ValueError('DataInput already present %s %s' % (element, datainput_description))
        if letter == 'C':
            datainputs[letter] = 1
        elif letter == 'Q':
            if len(element) == 1:
                datainputs[letter] = ('N', 8)
            else:
                second_letter = element[1]
                try:
                    if second_letter not in 'ANH':
                        raise ValueError()
                    length = int(element[2:])
                    if length < 4 or length > 64:
                        raise ValueError()
                except ValueError:
                    raise ValueError('Invalid challenge descriptor %s' % element)
                datainputs[letter] = (second_letter, length)
        elif letter == 'P':
            algo = str2hashalgo(element[1:] or 'SHA1')
            datainputs[letter] = algo
        elif letter == 'S':
            length = 64
            if element[1:]:
                try:
                    length = int(element[1:])
                except ValueError:
                    raise ValueError('Invalid session data descriptor %s' % element)
            datainputs[letter] = length
        elif letter == 'T':
            complement = element[1:] or '1M'
            try:
                length = 0
                if not re.match(r'^(\d+[HMS])+$', complement):
                    raise ValueError()
                parts = re.findall(r'\d+[HMS]', complement)
                for part in parts:
                    period = part[-1]
                    quantity = int(part[:-1])
                    length += quantity * PERIODS[period]
                datainputs[letter] = length
            except ValueError:
                raise ValueError('Invalid timestamp descriptor %s' % element)
        else:
            raise ValueError('Invalid datainput descriptor %s' % element)
    return DataInput(**datainputs)


class OcraSuite(object):
    def __init__(self, ocrasuite_description, crypto_function, data_input):
        self.ocrasuite_description = ocrasuite_description
        self.crypto_function = crypto_function
        self.data_input = data_input

    def __call__(self, key, **kwargs):
        data_input = self.ocrasuite_description.encode('ascii') + b'\0' + self.data_input(**kwargs)
        return self.crypto_function(key, data_input)

    def accept(self, response, key, **kwargs):
        return _utils.compare_digest(str(response), self(key, **kwargs))

    def __str__(self):
        return '<OcraSuite crypto_function:%s data_input:%s>' % (self.crypto_function, self.data_input)


def str2ocrasuite(ocrasuite_description):
    elements = ocrasuite_description.split(':')
    if len(elements) != 3:
        raise ValueError('Bad OcraSuite description %s' % ocrasuite_description)
    if elements[0] != OCRA_1:
        raise ValueError('Unsupported OCRA identifier %s' % elements[0])
    crypto_function = str2cryptofunction(elements[1])
    data_input = str2datainput(elements[2])
    return OcraSuite(ocrasuite_description, crypto_function, data_input)


class StateException(Exception):
    pass


DEFAULT_LENGTH = 20


class OCRAChallengeResponse(object):
    state = 1

    def __init__(self, key, ocrasuite_description, remote_ocrasuite_description=None):
        self.key = key
        self.ocrasuite = str2ocrasuite(ocrasuite_description)
        self.remote_ocrasuite = remote_ocrasuite_description is not None and str2ocrasuite(
            remote_ocrasuite_description
        )
        if not self.ocrasuite.data_input.Q:
            raise ValueError('Ocrasuite must have a Q descriptor')


def compute_challenge(Q):
    kind, length = Q
    try:
        r = xrange(0, length)
    except NameError:
        r = range(0, length)
    if kind == 'N':
        c = ''.join([random.choice(string.digits) for i in r])
    elif kind == 'A':
        alphabet = string.digits + string.ascii_letters
        c = ''.join([random.choice(alphabet) for i in r])
    elif kind == 'H':
        c = ''.join([random.choice(string.hexdigits) for i in r])
    else:
        raise ValueError('Q kind is unknown: %s' % kind)
    return c


class OCRAChallengeResponseServer(OCRAChallengeResponse):
    SERVER_STATE_COMPUTE_CHALLENGE = 1
    SERVER_STATE_VERIFY_RESPONSE = 2
    SERVER_STATE_FINISHED = 3

    def compute_challenge(self):
        if self.state != self.SERVER_STATE_COMPUTE_CHALLENGE:
            raise StateException()
        ocrasuite = self.remote_ocrasuite or self.ocrasuite
        self.challenge = compute_challenge(ocrasuite.data_input.Q)
        self.state = self.SERVER_STATE_VERIFY_RESPONSE
        return self.challenge

    def verify_response(self, response, **kwargs):
        if self.state != self.SERVER_STATE_VERIFY_RESPONSE:
            return StateException()
        ocrasuite = self.remote_ocrasuite or self.ocrasuite
        c = _utils.compare_digest(ocrasuite(self.key, Q=self.challenge, **kwargs), response)
        if c:
            self.state = self.SERVER_STATE_FINISHED
        return c


class OCRAChallengeResponseClient(OCRAChallengeResponse):
    def compute_response(self, challenge, **kwargs):
        return self.ocrasuite(self.key, Q=challenge, **kwargs)


class OCRAMutualChallengeResponseClient(OCRAChallengeResponse):
    CLIENT_STATE_COMPUTE_CLIENT_CHALLENGE = 1
    CLIENT_STATE_VERIFY_SERVER_RESPONSE = 2
    CLIENT_STATE_COMPUTE_CLIENT_RESPONSE = 3
    CLIENT_STATE_FINISHED = 4

    def compute_client_challenge(self, Qc=None):
        if self.state != self.CLIENT_STATE_COMPUTE_CLIENT_CHALLENGE:
            raise StateException()

        ocrasuite = self.remote_ocrasuite or self.ocrasuite
        self.client_challenge = Qc or compute_challenge(ocrasuite.data_input.Q)
        self.state = self.CLIENT_STATE_VERIFY_SERVER_RESPONSE
        return self.client_challenge

    def verify_server_response(self, response, challenge, **kwargs):
        if self.state != self.CLIENT_STATE_VERIFY_SERVER_RESPONSE:
            return StateException()
        self.server_challenge = challenge
        q = self.client_challenge + self.server_challenge
        ocrasuite = self.remote_ocrasuite or self.ocrasuite
        c = _utils.compare_digest(ocrasuite(self.key, Qsc=q, **kwargs), response)
        if c:
            self.state = self.CLIENT_STATE_COMPUTE_CLIENT_RESPONSE
        return c

    def compute_client_response(self, **kwargs):
        if self.state != self.CLIENT_STATE_COMPUTE_CLIENT_RESPONSE:
            return StateException()
        q = self.server_challenge + self.client_challenge
        rc = self.ocrasuite(self.key, Qsc=q, **kwargs)
        self.state = self.CLIENT_STATE_FINISHED
        return rc


class OCRAMutualChallengeResponseServer(OCRAChallengeResponse):
    SERVER_STATE_COMPUTE_SERVER_RESPONSE = 1
    SERVER_STATE_VERIFY_CLIENT_RESPONSE = 2
    SERVER_STATE_FINISHED = 3

    def compute_server_response(self, challenge, Qs=None, **kwargs):
        if self.state != self.SERVER_STATE_COMPUTE_SERVER_RESPONSE:
            raise StateException()
        self.client_challenge = challenge
        self.server_challenge = Qs or compute_challenge(self.ocrasuite.data_input.Q)
        q = self.client_challenge + self.server_challenge
        # no need for pin with server mode
        kwargs.pop('P', None)
        kwargs.pop('P_digest', None)
        rs = self.ocrasuite(self.key, Qsc=q, **kwargs)
        self.state = self.SERVER_STATE_VERIFY_CLIENT_RESPONSE
        return rs, self.server_challenge

    def verify_client_response(self, response, **kwargs):
        if self.state != self.SERVER_STATE_VERIFY_CLIENT_RESPONSE:
            raise StateException()
        q = self.server_challenge + self.client_challenge
        ocrasuite = self.remote_ocrasuite or self.ocrasuite
        c = _utils.compare_digest(ocrasuite(self.key, Qsc=q, **kwargs), response)
        if c:
            self.state = self.SERVER_STATE_FINISHED
        return c
