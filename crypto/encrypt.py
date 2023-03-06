from hashlib import sha256


def encrypt_and_sign(data, key):
    signature = sha256(data).digest()
    encryption = bytes([_a ^ _b for _a, _b in zip(data, key)])

    return signature + encryption
