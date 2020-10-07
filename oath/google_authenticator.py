# -*- Mode: Python; python-indent-offset: 4 -*-

'''
Google Authenticator API
------------------------

Google Authenticator is based on HOTP and TOTP. It provides a simple way of
provisionning an OTP generator through a new URL scheme.

This module provides parsing and high-level API over the classic HOTP and TOTP
APIs provided by the oath.hotp and oath.totp modules.
'''

try:
    from urlparse import urlparse, parse_qs
    from urllib import urlencode, quote
except ImportError:
    from urllib.parse import urlparse, parse_qs, urlencode, quote
import base64
import hashlib

from oath import _hotp as hotp
from oath import _totp as totp
from . import _utils

import binascii

__all__ = ('GoogleAuthenticator', 'from_b32key', 'GoogleAuthenticatorURI')

LABEL = 'label'
TYPE = 'type'
ALGORITHM = 'algorithm'
DIGITS = 'digits'
SECRET = 'secret'
COUNTER = 'counter'
PERIOD = 'period'
TOTP = 'totp'
HOTP = 'hotp'
DRIFT = 'drift'
ISSUER = 'issuer'


def lenient_b32decode(data):
    data = data.upper()  # Ensure correct case
    data += '=' * ((8 - len(data)) % 8)  # Ensure correct padding
    return base64.b32decode(data.encode('ascii'))


def parse_otpauth(otpauth_uri):
    if not otpauth_uri.startswith('otpauth://'):
        raise ValueError('Invalid otpauth URI', otpauth_uri)

    # urlparse in python 2.6 can't handle the otpauth:// scheme, skip it
    parsed_uri = urlparse(otpauth_uri[8:])

    params = dict(((k, v[0]) for k, v in parse_qs(parsed_uri.query).items()))
    params[LABEL] = parsed_uri.path[1:]
    params[TYPE] = parsed_uri.hostname

    if SECRET not in params:
        raise ValueError('Missing secret field in otpauth URI', otpauth_uri)
    try:
        params[SECRET] = _utils.tohex(lenient_b32decode(params[SECRET]))
    except TypeError:
        raise ValueError('Invalid base32 encoding of the secret field in ' 'otpauth URI', otpauth_uri)
    if ALGORITHM in params:
        params[ALGORITHM] = params[ALGORITHM].lower()
        if params[ALGORITHM] not in ('sha1', 'sha256', 'sha512', 'md5'):
            raise ValueError('Invalid value for algorithm field in otpauth ' 'URI', otpauth_uri)
    else:
        params[ALGORITHM] = 'sha1'
    try:
        params[ALGORITHM] = getattr(hashlib, params[ALGORITHM])
    except AttributeError:
        raise ValueError('Unsupported algorithm %s in othauth URI' % params[ALGORITHM], otpauth_uri)

    for key in (DIGITS, PERIOD, COUNTER):
        try:
            if key in params:
                params[key] = int(params[key])
        except ValueError:
            raise ValueError(
                'Invalid value for field %s in otpauth URI, must ' 'be a number' % key, otpauth_uri
            )
    if COUNTER not in params:
        params[COUNTER] = 0  # what else ?
    if DIGITS in params:
        if params[DIGITS] not in (6, 8):
            raise ValueError('Invalid value for field digits in othauth URI, it ' 'must 6 or 8', otpauth_uri)
    else:
        params[DIGITS] = 6
    if params[TYPE] == HOTP and COUNTER not in params:
        raise ValueError(
            'Missing field counter in otpauth URI, it is ' 'mandatory with the hotp type', otpauth_uri
        )
    if params[TYPE] == TOTP and PERIOD not in params:
        params[PERIOD] = 30
    return params


def from_b32key(b32_key, state=None):
    '''Some phone app directly accept a partial b32 encoding, we try to emulate that'''
    try:
        lenient_b32decode(b32_key)
    except TypeError:
        raise ValueError('invalid base32 value')
    return GoogleAuthenticator('otpauth://totp/xxx?%s' % urlencode({'secret': b32_key}), state=state)


class GoogleAuthenticator(object):
    def __init__(self, otpauth_uri, state=None):
        self.otpauth_uri = otpauth_uri
        self.parsed_otpauth_uri = parse_otpauth(otpauth_uri)
        self.generator_state = state or {}
        self.acceptor_state = state or {}

    @property
    def label(self):
        return self.parsed_otpauth_uri[LABEL]

    def generate(self, t=None):
        format = 'dec%s' % self.parsed_otpauth_uri[DIGITS]
        hash = self.parsed_otpauth_uri[ALGORITHM]
        secret = self.parsed_otpauth_uri[SECRET]
        state = self.generator_state
        if self.parsed_otpauth_uri[TYPE] == HOTP:
            if COUNTER not in state:
                state[COUNTER] = self.parsed_otpauth_uri[COUNTER]
            otp = hotp.hotp(secret, state[COUNTER], format=format, hash=hash)
            state[COUNTER] += 1
            return otp
        elif self.parsed_otpauth_uri[TYPE] == TOTP:
            period = self.parsed_otpauth_uri[PERIOD]
            return totp.totp(secret, format=format, period=period, hash=hash, t=t)
        else:
            raise NotImplementedError(self.parsed_otpauth_uri[TYPE])

    def accept(
        self, otp, hotp_drift=3, hotp_backward_drift=0, totp_forward_drift=1, totp_backward_drift=1, t=None
    ):
        format = 'dec%s' % self.parsed_otpauth_uri[DIGITS]
        hash = self.parsed_otpauth_uri[ALGORITHM]
        secret = self.parsed_otpauth_uri[SECRET]
        state = self.acceptor_state
        if self.parsed_otpauth_uri[TYPE] == HOTP:
            if COUNTER not in state:
                state[COUNTER] = self.parsed_otpauth_uri[COUNTER]
            ok, state[COUNTER] = hotp.accept_hotp(
                otp,
                secret,
                state[COUNTER],
                format=format,
                hash=hash,
                drift=hotp_drift,
                backward_drift=hotp_backward_drift,
            )
            return ok
        elif self.parsed_otpauth_uri[TYPE] == TOTP:
            period = self.parsed_otpauth_uri[PERIOD]
            if DRIFT not in state:
                state[DRIFT] = 0
            ok, state[DRIFT] = totp.accept_totp(
                secret,
                otp,
                format=format,
                period=period,
                forward_drift=totp_forward_drift,
                backward_drift=totp_backward_drift,
                drift=state[DRIFT],
                t=t,
            )
            return ok
        else:
            raise NotImplementedError(self.parsed_otpauth_uri[TYPE])


class GoogleAuthenticatorURI(object):
    """ used to create an URI for Google Authenticator, needs to be converted
        in QR afterwards
    """

    def __init__(self):
        """ constructor """
        return

    def generate(
        self, secret, type='totp', account='alex', issuer=None, algo='sha1', digits=6, init_counter=None
    ):
        """
        https://github.com/google/google-authenticator/wiki/Key-Uri-Format
        """

        args = {}
        uri = 'otpauth://{0}/{1}?{2}'

        try:
            # converts the secret to a 16 cars string
            a = binascii.unhexlify(secret)
            args[SECRET] = base64.b32encode(a).decode('ascii')
        except binascii.Error as ex:
            raise ValueError(str(ex))
        except Exception as ex:
            print(ex)
            raise ValueError('invalid secret format')

        if type not in [TOTP, HOTP]:
            raise ValueError('type should be totp or hotp, got ', type)
        if type != TOTP:
            args['type'] = type

        if algo not in ['sha1', 'sha256', 'sha512']:
            raise ValueError('algo should be sha1, sha256 or sha512, got ', algo)
        if algo != 'sha1':
            args['algorithm'] = algo

        if init_counter is not None:
            if type != HOTP:
                raise ValueError('type should be hotp when ', 'setting init_counter')

            if int(init_counter) < 0:
                raise ValueError('init_counter should be positive')
            args[COUNTER] = int(init_counter)

        digits = int(digits)
        if digits != 6 and digits != 8:
            raise ValueError('digits should be 6 or 8')
        if digits != 6:
            args[DIGITS] = digits

        args[PERIOD] = 30

        account = quote(account)
        if issuer is not None:
            account = quote(issuer) + ':' + account
            args[ISSUER] = issuer

        uri = uri.format(type, account, urlencode(args).replace("+", "%20"))

        return uri
