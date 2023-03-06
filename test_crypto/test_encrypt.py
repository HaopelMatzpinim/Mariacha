from crypto.encrypt import encrypt_and_sign


def test_encryption():
    assert encrypt_and_sign(b'abc', b'cba') == (
        b'\xbax\x16\xbf\x8f\x01\xcf\xeaAA@\xde]\xae"'
        b'#\xb0\x03a\xa3\x96\x17z\x9c\xb4\x10\xffa\xf2\x00\x15\xad',
        b'\x02\x00\x02'
    )


def test_encryption_two():
    assert encrypt_and_sign(b'ofndshsodk', b'qwlpotrhjo') == (
        b'l\x94\xf1\xd7;\x13\x12t\x1bR^\x87\xfeg\xc4D+\x81A.\xe9\xb9\xaa '
        b'\xac\xda\xf3c\xd6\xb8\xed\x01',
        b'\x1e\x11\x02\x14\x1c\x1c\x01\x07\x0e\x04'
    )


def test_encryption_three():
    assert encrypt_and_sign(b'sdfkjkpaos', b'jrtiqwoien') == (
        b'M%\xf6\x87\xe3\xa6\x0f~`&\xfffqBW\xff~\x01<6*\xf0 x\xe0\xa6\xc2\xe10'
        b'\xbb\r\xbf',
        b'\x19\x16\x12\x02\x1b\x1c\x1f\x08\n\x1d'
    )
