import sys

from scapy.all import StrFixedLenField, Packet, LongField

SIGNATURE_SIZE = 32

ENCRYPTION_HEADER_SIZE = SIGNATURE_SIZE + sys.getsizeof(int)

class EncryptionHeader(Packet):
    fields_desc = [
        StrFixedLenField('signature', None, SIGNATURE_SIZE),
        LongField('index', 0),
    ]



