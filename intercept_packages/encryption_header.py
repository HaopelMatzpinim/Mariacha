from scapy.all import StrFixedLenField, Packet, LongField

SIGNATURE_SIZE = 32


class EncryptionHeader(Packet):
    fields_desc = [
        StrFixedLenField('signature', None, SIGNATURE_SIZE),
        LongField('index', 0),
    ]
