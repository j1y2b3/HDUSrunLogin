# Convert by https://www.codeconvert.ai/javascript-to-python-converter from ./encodeinfo.js .

import base64
import json
import string

CUSTOM_ALPHABET = 'LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA'
STD_ALPHABET = string.ascii_uppercase + string.ascii_lowercase + string.digits + '+/'
ALPHABET_TABLE = str.maketrans(STD_ALPHABET, CUSTOM_ALPHABET)


def i32(x):
    """Emulate JavaScript ToInt32 wrapping."""
    x &= 0xFFFFFFFF
    return x - 0x100000000 if x & 0x80000000 else x

def ushr(x, n):
    """Emulate JavaScript >>> operator."""
    return i32((x & 0xFFFFFFFF) >> n)

def shl(x, n):
    """Emulate JavaScript << operator."""
    return i32(x << n)

def base64_encode(text):
    """Custom-alphabet base64 encoding of a string whose chars are bytes."""
    data = bytes(ord(ch) & 0xFF for ch in text)
    std = base64.b64encode(data).decode('ascii')
    return std.translate(ALPHABET_TABLE)

def s(a, b):
    c = len(a)
    v = []

    def ch(j):
        return ord(a[j]) if j < c else 0

    for i in range(0, c, 4):
        v.append(i32(ch(i) | shl(ch(i + 1), 8) | shl(ch(i + 2), 16) | shl(ch(i + 3), 24)))

    if b:
        v.append(c)
    return v

def l(a):
    parts = []
    for x in a:
        parts.append(
            chr(x & 0xFF)
            + chr((x >> 8) & 0xFF)
            + chr((x >> 16) & 0xFF)
            + chr((x >> 24) & 0xFF)
        )
    return ''.join(parts)

def encode(text, key):
    if text == '':
        return ''

    v = s(text, True)
    k = s(key, False)
    if len(k) < 4:
        k.extend([0] * (4 - len(k)))  # JS undefined behaves as 0 in bitwise ops

    n = len(v) - 1
    z = v[n]
    y = v[0]
    c = i32(0x9E3779B9)  # 0x86014019 | 0x183639A0
    q = 6 + 52 // (n + 1)
    d = 0

    while q > 0:
        q -= 1
        d = i32(d + c)
        e = ushr(d, 2) & 3

        for p in range(n):
            y = v[p + 1]
            m = i32(ushr(z, 5) ^ shl(y, 2))
            m = i32(m + (ushr(y, 3) ^ shl(z, 4) ^ (d ^ y)))
            m = i32(m + (k[(p & 3) ^ e] ^ z))
            z = v[p] = i32(v[p] + m)

        y = v[0]
        m = i32(ushr(z, 5) ^ shl(y, 2))
        m = i32(m + (ushr(y, 3) ^ shl(z, 4) ^ (d ^ y)))
        m = i32(m + (k[(n & 3) ^ e] ^ z))
        z = v[n] = i32(v[n] + m)

    return l(v)

def encode_info(info: dict, token: str):
    _info = json.dumps(info, separators=(',', ':'), ensure_ascii=False)
    return '{SRBX1}' + base64_encode(encode(_info, token))


if __name__ == "__main__":
    sample_info = {
        "username": '19051234',
        "password": 'MyPassword123',
        "ip": '10.150.246.44',
        "acid": '1',
        "enc_ver": 'srun_bx1'
    }
    sample_token = "5a4717f974090b75f6d31c204c1981b409a65edcfeac30954de1c6b04349d7c7"
    res = encode_info(sample_info, sample_token)
    print(res)
    print(res == "{SRBX1}pQdvKA1NaW4ItXrz5nSSJhVoPCWNTlIbf89n+7YF2SYV226W9Gv06RnOpJ761QKr9/tJyHBjdzwoYJQomU7j9prkAGYNXS244Tlrqhi1wkn+eGoOQNs/0N8QnPz9uR3AJp7Gc9b7j7oPLzdX")