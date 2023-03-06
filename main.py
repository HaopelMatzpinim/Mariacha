from scapy.layers.inet import *
from scapy.sendrecv import srloop, sendp, srp, sniff
import socket


def change_packet_header(packet):
    return packet


def encrypt_and_sign(data, key):
    return data


def encrypt(packet):
    return encrypt_and_sign(packet.build(), "key")


def send_packets_to_ip(dest_ip):
    def send_packets_to_interface(packet):
        encrypted_packet = encrypt(packet)
        including_header_packet = change_packet_header(encrypted_packet)
        packet_ready_to_send = Ether() / IP(dst=dest_ip) / ICMP() / including_header_packet
        sendp(packet_ready_to_send)
    return send_packets_to_interface


if __name__ == '__main__':
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind(('eth0', 0))

    s.send()
    # sniff(prn=send_packets_to_ip("172.16.28.21"))
