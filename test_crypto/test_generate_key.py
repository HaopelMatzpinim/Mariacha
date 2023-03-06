from crypto.generate_key import generate_key


def test_same_index():
    all_keys = [generate_key(i, 3) for i in range(10, 264)]

    assert sum(any(all_keys[-i] in s for s in all_keys[(-i + 1)::]) for i in range(len(all_keys))) != len(all_keys)


def test_diff_index():
    all_keys = [generate_key(32, i) for i in range(1000000)]

    assert len(all_keys) == len(set(all_keys))
