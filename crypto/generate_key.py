import random

SEED = b'\xc7v\x7fu\x8cEO\xe5hGc%\xb9LfNisFrVtq\xd9\xdcY\xcf\xb8\xab\x87>\xe2'


def generate_key(size, index):
    random.seed(int.from_bytes(SEED) ^ index)

    return random.getrandbits(size * 8).to_bytes(size, 'little')
