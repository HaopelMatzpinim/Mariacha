import pytest

from crypto.decrypt import decrypt_and_verify
from crypto.encrypt import encrypt_and_sign


@pytest.mark.parametrize("message, key",
                         [(b"hello world",
                           b"12345678910"),

                          (b"blue team is the best and red team wont stop us",
                           b"VzCq7uUWh8hvSrkrms555555Kgm2003YoavtheKingwithU"),

                          (b"",
                           b""),

                          (b"1",
                           b"333333333333333"),

                          (b"",
                           b"123"),
                          ])
def test_encrypt_and_decrypt_error(message, key):
    encrypted_message = encrypt_and_sign(message, key)
    decrypted_message = decrypt_and_verify(encrypted_message[1], encrypted_message[0], key)

    assert decrypted_message == message


@pytest.mark.parametrize("message, key",
                         [(b"hello world",
                           b"123"),

                          (b"123",
                           b"")
                          ])
def test_encrypt_and_decrypt(message, key):
    encrypted_message = encrypt_and_sign(message, key)
    with pytest.raises(Exception):
        decrypted_message = decrypt_and_verify(encrypted_message[1], encrypted_message[0], key)

        assert decrypted_message != message
