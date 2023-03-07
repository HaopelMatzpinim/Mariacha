from scapy import packet
from scapy.layers.inet import *
from scapy.all import *
from scapy.sendrecv import sendp, sniff
from intercept_packages.encryption_header import *
from crypto.generate_key import *
from crypto.encrypt import *
from crypto.decrypt import *

INDEX = 0
DEST_IP = '172.16.28.18'
PLAIN_MAC = 'f4:39:09:10:b4:a8'
ENCRYPTED_MAC = 'f4:39:09:10:b1:92'


def encrypt(packet):
    build_packet = packet.build()
    key = generate_key(len(build_packet), INDEX)
    return encrypt_and_sign(build_packet, key)


def decrypt(packet):
    encryption_header = EncryptionHeader(raw(packet.getlayer(Raw)))
    return decrypt_and_verify(encryption_header.getlayer(Raw).load,
                              encryption_header.signature,
                              generate_key(len(encryption_header.getlayer(Raw).load), encryption_header.index))


def plain_to_encrypted(packet):
    global INDEX

    signature, encrypted_packet = encrypt(packet)

    packet_ready_to_send = Ether() \
                           / IP(dst=DEST_IP) \
                           / EncryptionHeader(magic=DEFAULT_HEADER_START, signature=signature, index=INDEX) \
                           / Raw(encrypted_packet)
    INDEX += 1
    sendp(packet_ready_to_send)


def encrypted_to_plain(packet):
    try:
        raw = decrypt(packet)
        packet_ready_to_send = Ether() \
                               / IP(dst=DEST_IP) \
                               / Raw(raw)
        sendp(packet_ready_to_send)
    except (TypeError, AttributeError) as e:
        packet.show()
        print(type(e).__name__, e)
    except DecryptionError as e:
        print(type(e).__name__, e)
    except OSError:
        print(f'Error: package to long. len: {packet.len}')
    except struct.error as e:
        print(type(e).__name__, e)
    except Exception as e:
        print(f'unknown error. type: {type(e).__name__}, Error: {e}')


def separate_in_and_out(pkt):
    if pkt.dst == PLAIN_MAC:
        plain_to_encrypted(pkt)
    elif pkt.dst == ENCRYPTED_MAC and\
            hasattr(packet, 'load') and\
            len(packet.load) <= ENCRYPTION_HEADER_SIZE and\
            not packet.load.startswith(DEFAULT_HEADER_START):
        encrypted_to_plain(pkt)


def sniff_all():
    sniff(prn=separate_in_and_out)
