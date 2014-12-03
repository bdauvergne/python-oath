Python OATH
===========

.. image:: https://travis-ci.org/bdauvergne/python-oath.png?branch=master
        :target: https://travis-ci.org/bdauvergne/python-oath

.. image:: https://pypip.in/d/oath/badge.png
        :target: https://crate.io/packages/oath/

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
