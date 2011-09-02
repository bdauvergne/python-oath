import time
import hashlib
import datetime
import calendar

'''
   TOTP implementation

   See http://tools.ietf.org/html/draft-mraihi-totp-timebased-06
'''


from hotp import hotp

__ALL__ = ('totp', 'accept_totp')

def totp(key, format='dec8', period=30, t=None, hash=hashlib.sha1):
    '''
       Compute a TOTP value as prescribed by OATH specifications.

       :params key:
           the TOTP key given as an hexadecimal string
       :params format:
           the output format, can be:
              - hex40, for a 40 characters hexadecimal format,
              - dec4, for a 4 characters decimal format,
              - dec6,
              - dec7, or
              - dec8
           it default to dec6.
       :params period:
           a positive integer giving the period between changes of the OTP
           value, as seconds, it defaults to 30.
       :params t:
           a positive integer giving the current time as seconds since EPOCH
           (1st January 1970 at 00:00 GMT), if None we use time.time(); it
           defaults to None;
       :params hash:
           the hash module (usually from the hashlib package) to use,
           it defaults to hashlib.sha1.

       :returns:
           a string representation of the OTP value (as instructed by the format parameter).


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

def accept_totp( response, key, format='dec8', period=30, t=None,
        hash=hashlib.sha1, forward_drift=1, backward_drift=1, drift=0):
    '''
       Validate a TOTP value inside a window of 
       [drift-bacward_drift:drift+forward_drift] of time steps.
       Where drift is the drift obtained during the last call to accept_totp.

       :params response:
           a string representing the OTP to check, its format should correspond
           to the format parameter (it's not mandatory, it is part of the
           checks),
       :params key:
           the TOTP key given as an hexadecimal string
       :params format:
           the output format, can be:
              - hex40, for a 40 characters hexadecimal format,
              - dec4, for a 4 characters decimal format,
              - dec6,
              - dec7, or
              - dec8
           it default to dec6.
       :params period:
           a positive integer giving the period between changes of the OTP
           value, as seconds, it defaults to 30.
       :params t:
           a positive integer giving the current time as seconds since EPOCH
           (1st January 1970 at 00:00 GMT), if None we use time.time(); it
           defaults to None;
       :params hash:
           the hash module (usually from the hashlib package) to use,
           it defaults to hashlib.sha1.
       :params forward_drift:
           how much we accept the client clock to advance, as a number of
           periods,  i.e. if the period is 30 seconds, a forward_drift of 2,
           allows at most a clock a drift of 90 seconds;

                   Schema:
                          .___ Current time
                          |
                   0      v       + 30s         +60s              +90s
                   [ current_period |   period+1  |   period+2     [

           it defaults to 1.

       :params backward_drift:
           how much we accept the client clock to backstep; it defaults to 1.
       :params drift:
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
    '''
    t = t or time.time()
    for i in range(-backward_drift,forward_drift+1):
        d = (drift+i) * period
        if totp(key, format=format, period=period, hash=hash, t=t+d) == str(response):
            return True, drift+i
    return False, 0
