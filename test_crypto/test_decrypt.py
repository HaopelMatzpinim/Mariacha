from decrypt import decryptedVerification
from hashlib import sha256


def test_decryptedVerification():
    assert decryptedVerification(b'*\x0f\\i\xd0\x1a>,\x8e\xbe'
                                 , sha256(b'\x99\xfa\xca\x9c\xfd\x03?\xda\xfcv')
                                 , b'\xb3\xf5\x96\xf5-\x19\x01\xf6r\xc8') \
    == b'\x99\xfa\xca\x9c\xfd\x03?\xda\xfcv'


def test_decryptedVerification_two():
    assert decryptedVerification(b'\x9c\xae\x9c\\\xff\x122\x02\xf4\xa1'
                                 , sha256(b'\xb1\xac\xefn\x1d\xd8{\xe3\x8f^')
                                 , b'-\x02s2\xe2\xcaI\xe1{\xff') \
    == b'\xb1\xac\xefn\x1d\xd8{\xe3\x8f^'


def test_decryptedVerification_three():
    assert decryptedVerification(b'\x99\x8fD<\xa8\xfdcY\x17\xe5'
                                 , sha256(b'\x92b\x00\x027b\xb8u)\xf2')
                                 , b'\x0b\xedD>\x9f\x9f\xdb,>\x17') \
    == b'\x92b\x00\x027b\xb8u)\xf2'


def test_decryptedVerification_four():
    assert decryptedVerification(b'\x10\xa3\x17d\x9c%?\xc4+\x85'
                                 , sha256(b'\x99\xe8\xe4B\xa34\x90:\xd0\xad')
                                 , b'\x89K\xf3&?\x11\xaf\xfe\xfb(') \
    == b'\x99\xe8\xe4B\xa34\x90:\xd0\xad'


def test_decryptedVerification_five():
    assert decryptedVerification(b'O\xa9r:\x96\x99\xe0Zg\x1f'
                                 , sha256(b'\x98\xf7\x85\xf9\xab\x06QK3/')
                                 , b'\xd7^\xf7\xc3=\x9f\xb1\x11T0') \
    == b'\x98\xf7\x85\xf9\xab\x06QK3/'


