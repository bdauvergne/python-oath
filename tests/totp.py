import unittest
import binascii
import hashlib

from oath import accept_totp

def parse_tv(tv):
    test_vectors  = [ [ cell.strip() for cell in line.strip(' |').split('|') ] for line in tv.splitlines()]
    test_vectors  = [ line for line in test_vectors if line[0] and len(line) > 3 ]
    return test_vectors

class Totp(unittest.TestCase):
    key_seed = '1234567890'.encode('ascii') # no effect in Python 2.x but makes a bytes intance in Python 3.x
    key_sha1 = binascii.hexlify(key_seed*2).decode('ascii')
    key_sha256 = binascii.hexlify(key_seed*3+'12'.encode('ascii')).decode('ascii')
    key_sha512 = binascii.hexlify(key_seed*6+'1234'.encode('ascii')).decode('ascii')

    tv = parse_tv('''|      59     |  1970-01-01  | 0000000000000001 | 94287082 |  SHA1  |
   |             |   00:00:59   |                  |          |        |
   |      59     |  1970-01-01  | 0000000000000001 | 46119246 | SHA256 |
   |             |   00:00:59   |                  |          |        |
   |      59     |  1970-01-01  | 0000000000000001 | 90693936 | SHA512 |
   |             |   00:00:59   |                  |          |        |
   |  1111111109 |  2005-03-18  | 00000000023523EC | 07081804 |  SHA1  |
   |             |   01:58:29   |                  |          |        |
   |  1111111109 |  2005-03-18  | 00000000023523EC | 68084774 | SHA256 |
   |             |   01:58:29   |                  |          |        |
   |  1111111109 |  2005-03-18  | 00000000023523EC | 25091201 | SHA512 |
   |             |   01:58:29   |                  |          |        |
   |  1111111111 |  2005-03-18  | 00000000023523ED | 14050471 |  SHA1  |
   |             |   01:58:31   |                  |          |        |
   |  1111111111 |  2005-03-18  | 00000000023523ED | 67062674 | SHA256 |
   |             |   01:58:31   |                  |          |        |
   |  1111111111 |  2005-03-18  | 00000000023523ED | 99943326 | SHA512 |
   |             |   01:58:31   |                  |          |        |
   |  1234567890 |  2009-02-13  | 000000000273EF07 | 89005924 |  SHA1  |
   |             |   23:31:30   |                  |          |        |
   |  1234567890 |  2009-02-13  | 000000000273EF07 | 91819424 | SHA256 |
   |             |   23:31:30   |                  |          |        |
   |  1234567890 |  2009-02-13  | 000000000273EF07 | 93441116 | SHA512 |
   |             |   23:31:30   |                  |          |        |
   |  2000000000 |  2033-05-18  | 0000000003F940AA | 69279037 |  SHA1  |
   |             |   03:33:20   |                  |          |        |
   |  2000000000 |  2033-05-18  | 0000000003F940AA | 90698825 | SHA256 |
   |             |   03:33:20   |                  |          |        |
   |  2000000000 |  2033-05-18  | 0000000003F940AA | 38618901 | SHA512 |
   |             |   03:33:20   |                  |          |        |
   | 20000000000 |  2603-10-11  | 0000000027BC86AA | 65353130 |  SHA1  |
   |             |   11:33:20   |                  |          |        |
   | 20000000000 |  2603-10-11  | 0000000027BC86AA | 77737706 | SHA256 |
   |             |   11:33:20   |                  |          |        |
   | 20000000000 |  2603-10-11  | 0000000027BC86AA | 47863826 | SHA512 |
   |             |   11:33:20   |                  |          |        |''')


    hash_algos = {
            'SHA1': {
                'key': key_sha1,
                'alg': hashlib.sha1, },
            'SHA256': {
                'key': key_sha256,
                'alg': hashlib.sha256, },
            'SHA512': {
                'key': key_sha512,
                'alg': hashlib.sha512, },
    }

    def test_totp(self):
        for t, _, _, response, algo_key in self.tv:
            algo = self.hash_algos[algo_key]
            self.assertTrue(accept_totp(algo['key'], response, t=int(t),
                hash=algo['alg'], format='dec8'))

    def test_totp_unicode(self):
        accept_totp(u'3133327375706e65726473', u'4e4ba93d', format='hex', period=1800)
