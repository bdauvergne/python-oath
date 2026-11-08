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

CHANGELOG
=========

Soon
----

- migrate to PEP517 build system

1.4.5
-----

- fix licensing metadata in setup.py, license is BSD 3-clause not MIT
- fix ci workflow
- fix typos (Tim Gates)
- fix dead declaration for test_suite in setup.py

1.4.4
-----
- add long description

1.4.3
-----

- fix deprecation warning with python 3.7
