import unittest


class GoogleAuthenticator(unittest.TestCase):
    def test_simple(self):
        from oath.google_authenticator import from_b32key

        vectors = (
            # generated from http://gauth.apps.gbraad.nl/
            (1391203240, 'GG', '762819'),
            (1391203342, 'FF', '737839'),
        )
        for t, b32_key, result in vectors:
            self.assertEqual(from_b32key(b32_key).generate(t=t), result)

    def test_parse_url(self):
        from oath.google_authenticator import GoogleAuthenticator

        vectors = (
            (1391203240, 'otpauth://totp/xxx?secret=GG', '762819'),
            (1391203342, 'otpauth://totp/xxx?secret=FF', '737839'),
        )
        for t, uri, result in vectors:
            self.assertEqual(GoogleAuthenticator(uri).generate(t=t), result)

    def test_generate_accept(self):
        from oath.google_authenticator import from_b32key

        secret = 'GG'
        gauth = from_b32key(secret)
        self.assertTrue(gauth.accept(gauth.generate()))
        self.assertFalse(gauth.accept('111111'))


class GoogleAuthenticatorURI(unittest.TestCase):
    def test_uri_odd_length(self):
        from oath.google_authenticator import GoogleAuthenticatorURI

        try:
            GoogleAuthenticatorURI().generate('ECE')
        except ValueError:
            return

        assert False, "should not generate based on a odd number of caracters secret"

    def test_type_error(self):
        from oath.google_authenticator import GoogleAuthenticatorURI

        try:
            GoogleAuthenticatorURI().generate('ECEA', type='totp')
            GoogleAuthenticatorURI().generate('ECEA', type='hotp')
        except ValueError:
            assert False, "type totp and hotp should be accepted"

        try:
            GoogleAuthenticatorURI().generate('ECEA', type='ukn')
        except ValueError:
            return

        assert False, "only totp and hotp types are accepted"

    def test_algo_error(self):
        from oath.google_authenticator import GoogleAuthenticatorURI

        try:
            GoogleAuthenticatorURI().generate('ECEA', algo='sha1')
            GoogleAuthenticatorURI().generate('ECEA', algo='sha256')
            GoogleAuthenticatorURI().generate('ECEA', algo='sha512')
        except ValueError:
            assert False, "algo sha1, sha256 and sha512 should be accepted"

        try:
            GoogleAuthenticatorURI().generate('ECEA', algo='ukn')
        except ValueError:
            return

        assert False, "only sha1, sha256 and sha512 algo should be accepted"

    def test_counter_error(self):
        from oath.google_authenticator import GoogleAuthenticatorURI

        try:
            GoogleAuthenticatorURI().generate('ECEA', init_counter=12)
        except ValueError:
            None

        try:
            GoogleAuthenticatorURI().generate('ECEA', init_counter=12, type='hotp')
        except ValueError:
            assert False, "hotp and counter=12 should be accepted"

        try:
            GoogleAuthenticatorURI().generate('ECEA', init_counter=-1, type='hotp')
        except ValueError:
            None

    def random_base32(self, length=16, random=None, chars=list('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')):

        # Use secrets module if available (Python version >= 3.6) per PEP 506
        try:
            import secrets

            random = secrets.SystemRandom()
        except ImportError:
            import random as _random

            random = _random.SystemRandom()

        return ''.join(random.choice(chars) for _ in range(length))

    def test_reverse_uri_1(self):
        from oath.google_authenticator import GoogleAuthenticatorURI
        from oath.google_authenticator import parse_otpauth
        import base64
        import binascii

        k = self.random_base32()
        a = base64.b32decode(k.encode('ascii'))
        key = binascii.hexlify(a).decode('ascii')

        u = GoogleAuthenticatorURI().generate(key, issuer='meta-x org', account='ach@meta-x.org')

        a = parse_otpauth(u)

        if a['secret'] != key:
            assert False, "bad key"

        if a['type'] != 'totp':
            assert False, "bad type"

        if a['counter'] != 0:
            assert False, "bad counter"

        if a['digits'] != 6:
            assert False, "bad digits"

    def test_reverse_uri_2(self):
        from oath.google_authenticator import GoogleAuthenticatorURI
        from oath.google_authenticator import parse_otpauth
        import base64
        import binascii

        k = self.random_base32()
        a = base64.b32decode(k.encode('ascii'))
        key = binascii.hexlify(a).decode('ascii')

        u = GoogleAuthenticatorURI().generate(
            key, issuer='meta-x org', account='ach@meta-x.org', type='hotp', algo='sha256', init_counter=8
        )

        a = parse_otpauth(u)

        if a['secret'] != key:
            assert False, "bad key"

        if a['type'] != 'hotp':
            assert False, "bad type"

        if a['counter'] != 8:
            assert False, "bad counter"

        if a['digits'] != 6:
            assert False, "bad digits"
