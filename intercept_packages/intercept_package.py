from scapy.layers.inet import *
from scapy.all import *
from scapy.sendrecv import sendp, sniff
from intercept_packages.encryption_header import *
from crypto.generate_key import generate_key
from crypto.encrypt import encrypt_and_sign
from crypto.decrypt import *

INDEX = 0
DEST_MAC = get_if_hwaddr(conf.iface)


def encrypt(packet):
    build_packet = packet.build()
    return encrypt_and_sign(build_packet, generate_key(len(build_packet), INDEX))


def decrypt(packet):
    encryption_header = EncryptionHeader(raw(packet.getlayer(Raw)))
    return decrypt_and_verify(encryption_header.getlayer(Raw).load,
                              encryption_header.signature,
                              generate_key(len(encryption_header.getlayer(Raw).load), encryption_header.index))


def plain_to_encrypted(packet):
    global INDEX

    signature, encrypted_packet = encrypt(packet)

    packet_ready_to_send = Ether(dst=DEST_MAC) \
                           / EncryptionHeader(signature=signature, index=INDEX) \
                           / Raw(encrypted_packet)
    INDEX += 1
    sendp(packet_ready_to_send)


def encrypted_to_plain(packet):
    try:
        if packet.len <= ENCRYPTION_HEADER_SIZE:
            return
        raw = decrypt(packet)
        packet_ready_to_send = Ether(dst=DEST_MAC) / Raw(raw)
        sendp(packet_ready_to_send)
    except (TypeError, AttributeError) as e:
        print(e)
    except DecryptionError:
        pass
    except OSError:
        print(f'Error: package to long. len: {packet.len}')
    except struct.error:
        pass
    except Exception as e:
        print(f'unknown error. type: {type(e).__name__}, Error: {e}')


def sniff_all():
    # sniff(prn=plain_to_encrypted)
    sniff(prn=encrypted_to_plain)
