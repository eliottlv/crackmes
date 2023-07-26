#!/usr/bin/env python3

"""
Encrypt a string with a 2 bytes randomly chosen (and rotating) key.
If the string is not even, a 0x00 padding byte is added.

Arg1 : the string to encrypt
Arg2 (optional) : the number of encryption rounds

"""

from os import urandom
from sys import argv

# Rotate bits right
def ror(val, r_bits, max_bits):
    return \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

# How many passes
count = 1
if len(argv) == 3:
    count = int(argv[2])

# Data to encrypt
data = list(argv[1].encode())

# Pad with 0x00 byte
if (len(data) % 2) != 0:
    data.append(0)

# Zip bytes by pairs of 2 bytes.
data_even = [i for idx, i in enumerate(data) if idx%2 == 0]
data_not_even = [i for idx, i in enumerate(data) if idx%2 == 1]
data = list(zip(data_even, data_not_even))

# Results
result = data.copy()

# Encrypt with "count" rounds
for i in range(0, count):
    key = [urandom(1), urandom(1)] # Random key
    print(f"key{i}   = 0x{key[0].hex()}{key[1].hex()}")
    for idx, byte in enumerate(result):
        local_key = ror((int.from_bytes(key[0]) << 8) | int.from_bytes(key[1]), idx*2, 16)
        res = ((byte[0] << 8) | byte[1]) ^ local_key
        result[idx] = (res >> 8, res & 0xff)

result_str = ""
for i in data:
    result_str += "0x" + bytearray([i[0], i[1]]).hex() + ","
result_str = result_str[:-1]
print(f"orig   = {result_str}")

result_str = ""
for i in result:
    result_str += "0x" + bytearray([i[0], i[1]]).hex() + ","
result_str = result_str[:-1]
print(f"result = {result_str}")
