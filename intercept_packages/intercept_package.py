from scapy import packet
from scapy.layers.inet import *
from scapy.all import *
from scapy.sendrecv import sendp, sniff
from intercept_packages.encryption_header import *
from crypto.generate_key import *
from crypto.encrypt import *
from crypto.decrypt import *
import os

INDEX = 0
# DEST_IP = DEST_IP
PLAIN_IP = os.environ.get('PLAIN_IP')
ENCRYPTED_IP = os.environ.get('ENCRYPTED_IP')



def encrypt(packet):
    build_packet = packet.build()
    key = generate_key(len(packet.getlayer("Raw").load), INDEX)
    return encrypt_and_sign(packet.getlayer("Raw").load, key)


def decrypt(packet):
    encryption_header = EncryptionHeader(packet.build()[len(Ether()) + len(IP()):])
    return decrypt_and_verify(encryption_header.getlayer(Raw).load,
                              encryption_header.signature,
                              generate_key(len(encryption_header.getlayer(Raw).load), encryption_header.index))


def plain_to_encrypted(packet):
    global INDEX

    signature, encrypted_packet = encrypt(packet)

    packet_ready_to_send = IP(dst=ENCRYPTED_IP, proto=1) \
        / EncryptionHeader(magic=DEFAULT_HEADER_START, signature=signature, index=INDEX) \
        / Raw(encrypted_packet)

    INDEX += 1
    send(packet_ready_to_send)


def encrypted_to_plain(packet):
    try:
        packet.show()
        raw = decrypt(packet)
        packet_ready_to_send = IP(dst=PLAIN_IP, proto=1) / Raw(raw)
        send(packet_ready_to_send)
    except DecryptionError as e:
        print(type(e).__name__, e)
    except OSError:
        print(f'Error: package to long. len: {packet.len}')
    except Exception as e:
        print(f'unknown error. type: {type(e).__name__}, Error: {e}')


def separate_in_and_out(pkt):
    if pkt[IP].src == PLAIN_IP:
        plain_to_encrypted(pkt)
    elif pkt[IP].src == ENCRYPTED_IP and pkt[EncryptionHeader].magic == DEFAULT_HEADER_START:
        encrypted_to_plain(pkt)


def sniff_all():
    sniff(prn=separate_in_and_out, iface=['eth0', 'eth1'])
