from scapy.layers.inet import *
from scapy.all import Raw
from scapy.sendrecv import sendp, sniff
from intercept_packages.encryption_header import EncryptionHeader
from crypto.generate_key import generate_key
from crypto.encrypt import encrypt_and_sign


def encrypt(packet):
    build_packet = packet.build()
    return encrypt_and_sign(build_packet, generate_key(len(build_packet), 0))


def send_packets_to_ip(dest_ip):
    def send_packets_to_interface(packet):
        signature, encrypted_packet = encrypt(packet)

        if EncryptionHeader not in packet:
            packet_ready_to_send = Ether(type=0xDED) \
                / EncryptionHeader(signature=signature, index=13) \
                / Raw(encrypted_packet)

        sendp(packet_ready_to_send)

    return send_packets_to_interface


if __name__ == '__main__':
    sniff(prn=send_packets_to_ip("localhost"))
