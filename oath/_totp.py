import time
import hashlib
import datetime
import calendar

from . import _utils

'''
:mod:`totp` -- RFC6238 - OATH TOTP implementation
=================================================

.. module:: parrot
  :platform: any
  :synosis: implement a time indexed one-time password algorithm based on a HMAC crypto function as specified in RFC6238
.. moduleauthor:: Benjamin Dauvergne <benjamin.dauvergne@gmail.com>

'''


from ._hotp import hotp

__all__ = ('totp', 'accept_totp')


def totp(key, format='dec6', period=30, t=None, hash=hashlib.sha1):
    '''
       Compute a TOTP value as prescribed by OATH specifications.

       :param key:
           the TOTP key given as an hexadecimal string
       :param format:
           the output format, can be:
              - hex, for a variable length hexadecimal format,
              - hex-notrunc, for a 40 characters hexadecimal non-truncated format,
              - dec4, for a 4 characters decimal format,
              - dec6,
              - dec7, or
              - dec8
           it defaults to dec6.
       :param period:
           a positive integer giving the period between changes of the OTP
           value, as seconds, it defaults to 30.
       :param t:
           a positive integer giving the current time as seconds since EPOCH
           (1st January 1970 at 00:00 GMT), if None we use time.time(); it
           defaults to None;
       :param hash:
           the hash module (usually from the hashlib package) to use,
           it defaults to hashlib.sha1.

       :returns:
           a string representation of the OTP value (as instructed by the format parameter).
       :type: str
    '''
    if t is None:
        t = int(time.time())
    else:
        if isinstance(t, datetime.datetime):
            t = calendar.timegm(t.utctimetuple())
        else:
            t = int(t)
    T = int(t / period)
    return hotp(key, T, format=format, hash=hash)


def accept_totp(
    key,
    response,
    format='dec6',
    period=30,
    t=None,
    hash=hashlib.sha1,
    forward_drift=1,
    backward_drift=1,
    drift=0,
):
    '''
       Validate a TOTP value inside a window of 
       [drift-bacward_drift:drift+forward_drift] of time steps.
       Where drift is the drift obtained during the last call to accept_totp.

       :param response:
           a string representing the OTP to check, its format should correspond
           to the format parameter (it's not mandatory, it is part of the
           checks),
       :param key:
           the TOTP key given as an hexadecimal string
       :param format:
           the output format, can be:
              - hex40, for a 40 characters hexadecimal format,
              - dec4, for a 4 characters decimal format,
              - dec6,
              - dec7, or
              - dec8
           it default to dec6.
       :param period:
           a positive integer giving the period between changes of the OTP
           value, as seconds, it defaults to 30.
       :param t:
           a positive integer giving the current time as seconds since EPOCH
           (1st January 1970 at 00:00 GMT), if None we use time.time(); it
           defaults to None;
       :param hash:
           the hash module (usually from the hashlib package) to use,
           it defaults to hashlib.sha1.
       :param forward_drift:
           how much we accept the client clock to advance, as a number of
           periods,  i.e. if the period is 30 seconds, a forward_drift of 2,
           allows at most a clock a drift of 90 seconds;

                   Schema:
                          .___ Current time
                          |
                   0      v       + 30s         +60s              +90s
                   [ current_period |   period+1  |   period+2     [

           it defaults to 1.

       :param backward_drift:
           how much we accept the client clock to backstep; it defaults to 1.
       :param drift:
           an absolute drift of the local clock to the client clock; use it to
           keep track of an augmenting drift with a client without augmenting
           the size of the window given by forward_drift and backward_dript; it
           defaults to 0, you should usually give as value the last value
           returned by accept_totp for this client (read further).

       :returns:
           a pair (v,d) where v is a boolean giving the result, and d the
           needed drift to validate the value. The drift value should be saved
           relative to the current client. This saved value SHOULD be used in
           later calls to accept_totp in order to accept a slowly accumulating
           drift in the client token clock; on the server side you should use
           reliable source of time like an NTP server.
       :rtype: a two element tuple
    '''
    if t is None:
        t = int(time.time())
    for i in range(max(-divmod(t, period)[0], -backward_drift), forward_drift + 1):
        d = (drift + i) * period
        if _utils.compare_digest(totp(key, format=format, period=period, hash=hash, t=t + d), response):
            return True, drift + i
    return False, 0
