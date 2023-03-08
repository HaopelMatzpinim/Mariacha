from scapy.layers.inet import *
from scapy.all import *
from scapy.sendrecv import sendp, sniff
from intercept_packages.encryption_header import EncryptionHeader
from crypto.generate_key import generate_key
from crypto.encrypt import encrypt_and_sign
from crypto.decrypt import decrypt_and_verify

INDEX = 0
DEST_IP = '127.0.0.1'

def encrypt(packet):
    build_packet = packet.build()
    key = generate_key(len(build_packet), INDEX)
    return encrypt_and_sign(build_packet, key)


def decrypt(packet):
    encryption_header = EncryptionHeader(packet.build()[len(Ether()) + len(IP()):])
    return decrypt_and_verify(encryption_header.getlayer(Raw).load,
                              encryption_header.signature,
                              generate_key(len(encryption_header.getlayer(Raw).load), encryption_header.index))


def plain_to_encrypted(packet):
    global INDEX

    signature, encrypted_packet = encrypt(packet)

    packet_ready_to_send = IP(dst=DEST_IP, proto=1) \
        / EncryptionHeader(signature=signature, index=INDEX) \
        / Raw(encrypted_packet)

    INDEX += 1
    send(packet_ready_to_send)


def encrypted_to_plain(packet):
    try:
        raw = decrypt(packet)
        packet_ready_to_send = Raw(raw)
        send(packet_ready_to_send)
    except Exception as e:
        print(e)


def sniff_all():
    sniff(prn=plain_to_encrypted)
    # sniff(prn=encrypted_to_plain)
