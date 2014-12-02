import unittest

from oath import (str2ocrasuite, OCRAMutualChallengeResponseClient,
        OCRAMutualChallengeResponseServer)
from oath._utils import fromhex

class OCRA(unittest.TestCase):
    key20 = fromhex('3132333435363738393031323334353637383930')
    key32 = fromhex('3132333435363738393031323334353637383930313233343536373839303132')
    key64 = fromhex('31323334353637383930313233343536373839303132333435363738393031323'
                        + '334353637383930313233343536373839303132333435363738393031323334')
    pin = '1234'
    pin_sha1 = fromhex('7110eda4d09e062aa5e4a390b0a572ac0d2c0220')

    tests = [ { 'ocrasuite': 'OCRA-1:HOTP-SHA1-6:QN08',
                'key': key20,
                'vectors': [
                    {'params': { 'Q': '00000000' }, 'result': '237653' },
                    {'params': { 'Q': '11111111' }, 'result': '243178' },
                    {'params': { 'Q': '22222222' }, 'result': '653583' },
                    {'params': { 'Q': '33333333' }, 'result': '740991' },
                    {'params': { 'Q': '44444444' }, 'result': '608993' },
                    {'params': { 'Q': '55555555' }, 'result': '388898' },
                    {'params': { 'Q': '66666666' }, 'result': '816933' },
                    {'params': { 'Q': '77777777' }, 'result': '224598' },
                    {'params': { 'Q': '88888888' }, 'result': '750600' },
                    {'params': { 'Q': '99999999' }, 'result': '294470' }
                ]
              },
              { 'ocrasuite': 'OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1',
                'key': key32,
                'vectors': [
                    {'params': { 'C': 0, 'Q': '12345678' }, 'result': '65347737' },
                    {'params': { 'C': 1, 'Q': '12345678' }, 'result': '86775851' },
                    {'params': { 'C': 2, 'Q': '12345678' }, 'result': '78192410' },
                    {'params': { 'C': 3, 'Q': '12345678' }, 'result': '71565254' },
                    {'params': { 'C': 4, 'Q': '12345678' }, 'result': '10104329' },
                    {'params': { 'C': 5, 'Q': '12345678' }, 'result': '65983500' },
                    {'params': { 'C': 6, 'Q': '12345678' }, 'result': '70069104' },
                    {'params': { 'C': 7, 'Q': '12345678' }, 'result': '91771096' },
                    {'params': { 'C': 8, 'Q': '12345678' }, 'result': '75011558' },
                    {'params': { 'C': 9, 'Q': '12345678' }, 'result': '08522129' }
                ]
              },
              { 'ocrasuite': 'OCRA-1:HOTP-SHA256-8:QN08-PSHA1',
                'key': key32,
                'vectors': [
                    {'params': { 'Q': '00000000' }, 'result': '83238735' },
                    {'params': { 'Q': '11111111' }, 'result': '01501458' },
                    {'params': { 'Q': '22222222' }, 'result': '17957585' },
                    {'params': { 'Q': '33333333' }, 'result': '86776967' },
                    {'params': { 'Q': '44444444' }, 'result': '86807031' }
                ]
              },
              { 'ocrasuite': 'OCRA-1:HOTP-SHA512-8:C-QN08',
                'key': key64,
                'vectors': [
                    {'params': { 'C': '00000', 'Q': '00000000' }, 'result': '07016083' },
                    {'params': { 'C': '00001', 'Q': '11111111' }, 'result': '63947962' },
                    {'params': { 'C': '00002', 'Q': '22222222' }, 'result': '70123924' },
                    {'params': { 'C': '00003', 'Q': '33333333' }, 'result': '25341727' },
                    {'params': { 'C': '00004', 'Q': '44444444' }, 'result': '33203315' },
                    {'params': { 'C': '00005', 'Q': '55555555' }, 'result': '34205738' },
                    {'params': { 'C': '00006', 'Q': '66666666' }, 'result': '44343969' },
                    {'params': { 'C': '00007', 'Q': '77777777' }, 'result': '51946085' },
                    {'params': { 'C': '00008', 'Q': '88888888' }, 'result': '20403879' },
                    {'params': { 'C': '00009', 'Q': '99999999' }, 'result': '31409299' }
                ]
              },
              { 'ocrasuite': 'OCRA-1:HOTP-SHA512-8:QN08-T1M',
                'key': key64,
                'vectors': [
                    {'params': { 'Q': '00000000', 'T_precomputed': int('132d0b6', 16) },
                        'result': '95209754' },
                    {'params': { 'Q': '11111111', 'T_precomputed': int('132d0b6', 16) },
                        'result': '55907591' },
                    {'params': { 'Q': '22222222', 'T_precomputed': int('132d0b6', 16) },
                        'result': '22048402' },
                    {'params': { 'Q': '33333333', 'T_precomputed': int('132d0b6', 16) },
                        'result': '24218844' },
                    {'params': { 'Q': '44444444', 'T_precomputed': int('132d0b6', 16) },
                        'result': '36209546' },
                ]
              },
            ]

    def test_str2ocrasuite(self):
        for test in self.tests:
            ocrasuite = str2ocrasuite(test['ocrasuite'])
            key = test['key']
            for vector in test['vectors']:
                params = vector['params']
                result = vector['result']
                if ocrasuite.data_input.P:
                    params['P'] = self.pin
                self.assertEqual(ocrasuite(key, **params), result)

    mut_suite = 'OCRA-1:HOTP-SHA256-8:QA08'

    mut_tests = [{'server_ocrasuite': 'OCRA-1:HOTP-SHA256-8:QA08',
                  'client_ocrasuite': 'OCRA-1:HOTP-SHA256-8:QA08',
                  'key': key32,
                  'challenges': [{ 'params': { 'Q': 'CLI22220SRV11110' },
                        'server_result': '28247970',
                        'client_result': '15510767' },
                      { 'params': { 'Q': 'CLI22221SRV11111' },
                        'server_result': '01984843',
                        'client_result': '90175646' },
                      { 'params': { 'Q': 'CLI22222SRV11112' },
                        'server_result': '65387857',
                        'client_result': '33777207' },
                      { 'params': { 'Q': 'CLI22223SRV11113' },
                        'server_result': '03351211',
                        'client_result': '95285278' },
                      { 'params': { 'Q': 'CLI22224SRV11114' },
                        'server_result': '83412541',
                        'client_result': '28934924' },]},
                 {'server_ocrasuite': 'OCRA-1:HOTP-SHA512-8:QA08',
                  'client_ocrasuite': 'OCRA-1:HOTP-SHA512-8:QA08-PSHA1',
                  'key': key64,
                  'challenges': [{ 'params': { 'Q': 'CLI22220SRV11110' },
                        'server_result': '79496648',
                        'client_result': '18806276' },
                                 { 'params': { 'Q': 'CLI22221SRV11111' },
                        'server_result': '76831980',
                        'client_result': '70020315' },
                                 { 'params': { 'Q': 'CLI22222SRV11112' },
                        'server_result': '12250499',
                        'client_result': '01600026' },
                                 { 'params': { 'Q': 'CLI22223SRV11113' },
                        'server_result': '90856481',
                        'client_result': '18951020' },
                                 { 'params': { 'Q': 'CLI22224SRV11114' },
                        'server_result': '12761449',
                        'client_result': '32528969' },
                      ]},
                ]


    def test_mutual_challenge_response_rfc(self):
        for test in self.mut_tests:
            for server_instance in test['challenges']:
                ocra_client = OCRAMutualChallengeResponseClient(test['key'],
                        test['client_ocrasuite'], test['server_ocrasuite'])
                ocra_server = OCRAMutualChallengeResponseServer(test['key'],
                        test['server_ocrasuite'], test['client_ocrasuite'])
                Q = server_instance['params']['Q']
                qc, qs = Q[:8], Q[8:]
                # ignore computed challenge
                ocra_client.compute_client_challenge(Qc=qc)
                rs, qs = ocra_server.compute_server_response(qc, Qs=qs)
                self.assertEqual(rs, server_instance['server_result'])
                self.assertTrue(ocra_client.verify_server_response(rs, qs))
                kwargs = {}
                if ocra_client.ocrasuite.data_input.P:
                    kwargs['P'] = self.pin
                rc = ocra_client.compute_client_response(**kwargs)
                self.assertEqual(rc, server_instance['client_result'])
                self.assertTrue(ocra_server.verify_client_response(rc, **kwargs))

    def test_mutual_challenge_response_simple(self):
        ocra_client = OCRAMutualChallengeResponseClient(self.key32,
                self.mut_suite)
        ocra_server = OCRAMutualChallengeResponseServer(self.key32,
                self.mut_suite)
        qc = ocra_client.compute_client_challenge()
        rs, qs = ocra_server.compute_server_response(qc)
        self.assertTrue(ocra_client.verify_server_response(rs, qs))
        rc = ocra_client.compute_client_response()
        self.assertTrue(ocra_server.verify_client_response(rc))


