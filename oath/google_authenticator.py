'''
Google Authenticator API
------------------------

Google Authenticator is based on HOTP and TOTP. It provides a simple way of
provisionning an OTP generator through a new URL scheme.

This module provides parsing and high-level API over the classic HOTP and TOTP
APIs provided by the oath.hotp and oath.totp modules.
'''

import re
import urlparse
import base64
import hashlib

from . import hotp
from . import totp

__ALL__ = ('GoogleAuthenticator',)

otpauth_re = re.compile(r'^otpauth://(?P<type>\w+)'
                        r'/(?P<labe>[^?]+)'
                        r'\?(?P<query>.*)$')

LABEL   =   'label'
TYPE    =    'type'
ALGORITHM = 'algorithm'
DIGITS  =  'digits'
SECRET  =  'secret'
COUNTER = 'counter'
PERIOD  =  'period'
TOTP    =    'totp'
HOTP    =    'hotp'
DRIFT    =   'drift'

def parse_otpauth(otpauth_uri):
    m = re.match(otpauth_re, otpauth_uri)
    if not m:
        raise ValueError('Invalid otpauth URI', otpauth_uri)
    d = m.groupdict()
    query_parse = urlparse.parse_qs(d['query'])
    if SECRET not in query_parse:
        raise ValueError('Missing secret field in otpauth URI', otpauth_uri)
    try:
        d[SECRET] = base64.b32decode(query_parse[SECRET])
    except TypeError:
        raise ValueError('Invalid base32 encoding of the secret field in '
                'otpauth URI', otpauth_uri)
    if ALGORITHM in query_parse:
        d[ALGORITHM] = query_parse[ALGORITHM].lower()
        if d[ALGORITHM] not in ('sha1', 'sha256', 'sha512', 'md5'):
            raise ValueError('Invalid value for algorithm field in otpauth '
                    'URI', otpauth_uri)
    else:
        d[ALGORITHM] = 'sha1'
    try:
        d[ALGORITHM] = getattr(hashlib, d[ALGORITHM])
    except AttributeError:
        raise ValueError('Unsupported algorithm %s in othauth URI' %
                d[ALGORITHM], otpauth_uri)
    for key in (DIGITS, PERIOD, COUNTER):
        try:
            if k in query_parse:
                d[k] = int(query_parse[k])
        except ValueError:
            raise ValueError('Invalid value for field %s in otpauth URI, must '
                    'be a number' % key, otpauth_uri)
    if COUNTER not in d:
        d[COUNTER] = 0 # what else ?
    if DIGITS in d:
        if d[DIGITS] not in (6,8):
            raise ValueError('Invalid value for field digits in othauth URI, it '
                    'must 6 or 8', otpauth_uri)
    else:
        d[DIGITS] = 6
    if d[TYPE] == HOTP and COUNTER not in d:
        raise ValueError('Missing field counter in otpauth URI, it is '
                'mandatory with the hotp type', otpauth_uri)
    if d[TYPE] == TOTP and PERIOD not in d:
        d[PERIOD] = 30
    return d

class GoogleAuthenticator(object):
    def __init__(otpauth_uri, state=None):
        self.otpauth_uri = otpauth_uri
        self.parsed_otpauth_uri = parse_otpauth(otpauth_uri)
        self.generator_state = state or {}
        self.acceptor_state = state or {}

    def generate(self):
        format = 'dec%s' % self.parsed_otpauth_uri[DIGITS]
        hash = self.parsed_otpauth_uri[ALGORITHM]
        secret = self.parsed_otpauth_uri[SECRET]
        state = self.generator_state
        if self.parsed_otpauth_uri[TYPE] == HOTP:
            if COUNTER not in state:
                state[COUNTER] = self.parsed_otpauth_uri[COUNTER]
            otp = hotp.hotp(secret, state[COUNTER], format=format,
                    hash=hash)
            state[COUNTER] += 1
            return otp
        elif self.parsed_otpauth_uri[TYPE] == TOTP:
            period = 'dec%s' % self.parsed_otpauth_uri[PERIOD]
            return hotp.totp(self.secret, format=format, period=period,
                    hash=hash)
        else:
            raise NotImplemented(self.parsed_otpauth_uri[TYPE])

    def accept(self, otp, hotp_drift=3, forward_drift=None,
            hotp_backward_drift=0, totp_forward_drift=1,
            totp_backward_drift=1, t=None):
        format = 'dec%s' % self.parsed_otpauth_uri[DIGITS]
        hash = self.parsed_otpauth_uri[ALGORITHM]
        secret = self.parsed_otpauth_uri[SECRET]
        state = self.acceptor_state
        if self.parsed_otpauth_uri[TYPE] == HOTP:
            if COUNTER not in state:
                state[COUNTER] = self.parsed_otpauth_uri[COUNTER]
            ok, state[COUNTER] = hotp.accept_hotp(otp, secret,
                    state[COUNTER], format=format, hash=hash,
                    drift=hotp_drift,
                    backward_drift=hotp_backward_drift)
            return ok
        elif self.parsed_otpauth_uri[TYPE] == TOTP:
            period = 'dec%s' % self.parsed_otpauth_uri[PERIOD]
            if DRIFT not in state:
                state[DRIFT] = 0
            ok, state[DRIFT] = totp.accept_totp(secret, otp, format=format,
                    period=period, forward_drift=totp_forward_drift,
                    backward_drift=totp_backward_drift, drift=state[DRIFT],
                    t=t)
            return ok
        else:
            raise NotImplemented(self.parsed_otpauth_uri[TYPE])
