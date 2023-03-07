from hashlib import sha256


class DecryptionError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


def decrypt_and_verify(recBytes, signature, key):
    decrypted_xor = bytes(a ^ b for a, b in zip(recBytes, key))

    if signature != sha256(decrypted_xor).digest():
        raise DecryptionError("The signature that was received did not match the signature that was calculated!")
    else:
        return decrypted_xor