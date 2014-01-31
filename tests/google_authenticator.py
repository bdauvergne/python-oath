import unittest

class GoogleAuthenticator(unittest.TestCase):
    def test_simple(self):
        from oath.google_authenticator import from_b32key
        l = (
                # generated from http://gauth.apps.gbraad.nl/
                (1391203240, 'GG', '762819'),
                (1391203342, 'FF', '737839'),
            )
        for t, b32_key, result in l:
            self.assertEquals(from_b32key(b32_key).generate(t=t), result)
