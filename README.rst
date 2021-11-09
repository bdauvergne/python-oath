Python OATH
===========

.. image:: https://github.com/bdauvergne/python-oath/workflows/CI/badge.svg
        :target: https://github.com/bdauvergne/python-oath/actions

.. image:: https://img.shields.io/pypi/dm/oath
        :target: https://pypi.org/project/oath/

python-oath is a package implementing the three main OATH specifications:
 - HOTP, an event based one-time password standard -- OTP -- using HMAC signatures,
 - TOTP, a time based OTP,
 - OCRA, a mixed OTP / signature system based on HOTP for complex use cases.

 It's Python 3 ready.

Getting started
===============

The main APIs are:

 - hotp, to generate a password.
 - accept_hotp, to check a received password,
 - totp and accept_totp, the same for the TOTP standard.
 - GoogleAuthenticator to parse Google Authenticator URI
 - from_b32key to create a a GoogleAuthenticator object from a simple base32 key
