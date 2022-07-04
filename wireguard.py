/*! SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

import math
import random

def gf(init=None):
    r = [0 for i in range(16)]
    if init is not None:
        for i in range(len(init)):
            r[i] = init[i]
    return r

def pack(o, n):
    b, m, t = gf(), gf(), gf()

    for i in range(16):
        t[i] = n[i]

        carry(t)
        carry(t)
        carry(t)

    for j in range(2):
        m[0] = t[0] - 65517
        for i in range(1, 15):
            m[i] = t[i] - 65535 - ((m[i - 1] >> 16) & 1)
            m[i - 1] &= 65535

    m[15] = t[15] - 32767 - ((m[14] >> 16) & 1)
    b = (m[15] >> 16) & 1
    m[14] &= 65535
    cswap(t, m, 1 - b)

    for i in range(16):
        o[2 * i] = t[i] & 255
        o[2 * i + 1] = t[i] >> 8

def carry(o):
    for i in range(16):
        o[(i + 1) % 16] += (1 if i < 15 else 38) * math.floor(o[i] / 65536)
        o[i] &= 65535

def cswap(p, q, b):
    c = ~(b - 1)
    for i in range(16):
        t = c & (p[i] ^ q[i])
        p[i] ^= t
        q[i] ^= t

def add(o, a, b):
    for i in range(16):
        o[i] = (a[i] + b[i]) | 0

def subtract(o, a, b):
    for i in range(16):
        o[i] = (a[i] - b[i]) | 0

def multmod(o, a, b):
    t = [0 for i in range(31)]

    for i in range(16):
        for j in range(16):
            t[i + j] += a[i] * b[j]

    for i in range(15):
        t[i] += 38 * t[i + 16]

    for i in range(16):
        o[i] = t[i]

    carry(o)
    carry(o)

def invert(o, i):
    c = gf()

    for a in range(16):
        c[a] = i[a]

    for a in range(253, -1, -1):
        multmod(c, c, c)
        if a != 2 and a != 4:
            multmod(c, c, i)

    for a in range(16):
        o[a] = c[a]

def clamp(z):
    z[31] = (z[31] & 127) | 64
    z[0] &= 248

def generatePublicKey(privateKey):
    r, z = [0 for i in range(32)], [0 for i in range(32)]
    a = gf([1])
    b = gf([9])
    c = gf()
    d = gf([1])
    e = gf()
    f = gf()
    _121665 = gf([56129, 1])
    _9 = gf([9])

    for i in range(32):
        z[i] = privateKey[i]

    clamp(z)

    for i in range(254, -1, -1):
        r = (z[i >> 3] >> (i & 7)) & 1
        cswap(a, b, r)
        cswap(c, d, r)
        add(e, a, c)
        subtract(a, a, c)
        add(c, b, d)
        subtract(b, b, d)
        multmod(d, e, e)
        multmod(f, a, a)
        multmod(a, c, a)
        multmod(c, b, e)
        add(e, a, c)
        subtract(a, a, c)
        multmod(b, a, a)
        subtract(c, d, f)
        multmod(a, c, _121665)
        add(a, a, d)
        multmod(c, c, a)
        multmod(a, d, f)
        multmod(d, b, _9)
        multmod(b, e, e)
        cswap(a, b, r)
        cswap(c, d, r)

    invert(c, c)
    multmod(a, a, c)
    pack(z, a)

    return z

def generatePresharedKey():
    privateKey = [random.randint(0,255) for x in range(32)]
    return privateKey

def generatePrivateKey():
    privateKey = generatePresharedKey()
    clamp(privateKey)
    return privateKey

def keyToBase64(key):
    base64_table = {'000000': 'A', '000001': 'B', '000010': 'C', '000011': 'D', '000100': 'E', '000101': 'F', '000110': 'G', '000111': 'H', '001000': 'I', '001001': 'J', '001010': 'K', '001011': 'L', '001100': 'M', '001101': 'N', '001110': 'O', '001111': 'P', '010000': 'Q', '010001': 'R', '010010': 'S', '010011': 'T', '010100': 'U', '010101': 'V', '010110': 'W', '010111': 'X', '011000': 'Y', '011001': 'Z', '011010': 'a', '011011': 'b', '011100': 'c', '011101': 'd', '011110': 'e', '011111': 'f', '100000': 'g', '100001': 'h', '100010': 'i', '100011': 'j', '100100': 'k', '100101': 'l', '100110': 'm', '100111': 'n', '101000': 'o', '101001': 'p', '101010': 'q', '101011': 'r', '101100': 's', '101101': 't', '101110': 'u', '101111': 'v', '110000': 'w', '110001': 'x', '110010': 'y', '110011': 'z', '110100': '0', '110101': '1', '110110': '2', '110111': '3', '111000': '4', '111001': '5', '111010': '6', '111011': '7', '111100': '8', '111101': '9', '111110': '+', '111111': '/'}

    key = "".join([format(i, '08b') for i in key])

    bit_split = [key[i-6:i] for i, j in enumerate(key, 1) if i % 6 == 0]

    if len(key) == len(bit_split) * 6:
        key = "".join([base64_table[i] for i in bit_split])

    else:
        if len(key) - len(bit_split) * 6 == 2:
            bit_split.append(key[len(bit_split) * 6:] + "0" * 4)
            key = "".join([base64_table[i] for i in bit_split]) + "=="
        else:
            bit_split.append(key[len(bit_split) * 6:] + "0" * 2)
            key = "".join([base64_table[i] for i in bit_split]) + "="

    return key

def generateKeypair():
    privateKey = generatePrivateKey()
    publicKey = generatePublicKey(privateKey)

    return keyToBase64(privateKey), keyToBase64(publicKey)

privateKey, publicKey = generateKeypair()

print(privateKey)
print(publicKey)
