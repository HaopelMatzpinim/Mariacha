from hashlib import sha256


def decrypt_and_verify(recBytes, signature, key):
    decrypted_xor = bytes(a ^ b for a, b in zip(recBytes, key))

    if signature.digest() != sha256(decrypted_xor).digest():
        raise Exception("The signature that was recieved" +
                        " did not match the signature that was calculated!")
    else:
        return decrypted_xor