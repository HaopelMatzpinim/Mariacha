from hashlib import sha256


def decryptedVerification(recBytes, signature, key):
    decrypted_xor = bytes(a ^ b for a, b in zip(recBytes, key))

    if signature.digest() != sha256(decrypted_xor).digest():
        raise Exception("The signature and the bytes were not equal!")
    else:
        return decrypted_xor