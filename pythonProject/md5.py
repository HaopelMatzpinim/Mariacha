from math import floor, sin


def md5(message):
    byte_array = bytearray(message, "ascii")
    byte_array.append(0x80)

    while len(byte_array) % 64 != 56:
        byte_array.append(0)

    length_in_bits = (len(message) * 8) & 0xffffffffffffffff
    byte_array += length_in_bits.to_bytes(8, "little")

    A = 0x67452301
    B = 0xEFCDAB89
    C = 0x98BADCFE
    D = 0x10325476

    init_temp = [A, B, C, D]

    F = lambda b, c, d: (b & c) | (~b & d)
    G = lambda b, c, d: (b & d) | (c & ~d)
    H = lambda b, c, d: b ^ c ^ d
    I = lambda b, c, d: c ^ (b | ~d)

    T = [floor(pow(2, 32) * abs(sin(i + 1))) for i in range(64)]

    def rotate_left(x, amount):
        x &= 0xFFFFFFFF

        return (x << amount | x >> (32 - amount)) & 0xFFFFFFFF

    for index in range(0, len(byte_array), 64):

        for innerIndex in range(64):
            if 0 <= innerIndex <= 15:
                k = innerIndex
                s = [7, 12, 17, 22]
                temp = F(B, C, D)
            elif 16 <= innerIndex <= 31:
                k = ((5 * innerIndex) + 1) % 16
                s = [5, 9, 14, 20]
                temp = G(B, C, D)
            elif 32 <= innerIndex <= 47:
                k = ((3 * innerIndex) + 5) % 16
                s = [4, 11, 16, 23]
                temp = H(B, C, D)
            elif 48 <= innerIndex <= 63:
                k = (7 * innerIndex) % 16
                s = [6, 10, 15, 21]
                temp = I(B, C, D)

            temp = temp + A + T[innerIndex] + int.from_bytes(byte_array[4 * k: 4 * k + 4], byteorder="little")
            A = D
            D = C
            C = B
            B += rotate_left(temp, s[innerIndex % 4]) & 0xFFFFFFFF

        for i, val in enumerate([A, B, C, D]):
            init_temp[i] += val
            init_temp[i] &= 0xFFFFFFFF

    processed_message = sum(buffer_content << (32 * i) for i, buffer_content in enumerate(init_temp))
    raw = processed_message.to_bytes(16, byteorder='little')

    return '{:032x}'.format(int.from_bytes(raw, byteorder='big'))
