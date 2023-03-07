from scapy.all import StrFixedLenField, Packet, LongField

DEFAULT_HEADER_START = b'abcd'
SIGNATURE_SIZE = 32

ENCRYPTION_HEADER_SIZE = len(DEFAULT_HEADER_START) + SIGNATURE_SIZE + 8


class EncryptionHeader(Packet):
    fields_desc = [
        StrFixedLenField('magic', DEFAULT_HEADER_START, len(DEFAULT_HEADER_START)),
        StrFixedLenField('signature', None, SIGNATURE_SIZE),
        LongField('index', 0),
    ]
