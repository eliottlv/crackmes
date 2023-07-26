#!/usr/bin/env python3

"""
Encrypt a string with a 2 bytes randomly chosen (and rotating) key.
If the string is not even, a 0x00 padding byte is added.

Arg1 : the raw binary asm file to encrypt
"""

from os import urandom
from sys import argv

# Read file & gen key
data = list(open(argv[1], mode="rb").read())
key = list(urandom(8))

# Print key
print("key dq 0x" + bytearray(key).hex())

# Pad code with nop instr
pad_len = 8 - (len(data) % 8)
if pad_len != 0:
    data.extend([0x90 for i in range(0, pad_len)])

# Pack to 8 bytes (little endian)
data_pack = []
for idx in range(0, len(data), 8):
    rev_seq = list(reversed(data[idx:idx+8]))
    for idx2 in range(0, len(rev_seq)):
        rev_seq[idx2] = rev_seq[idx2] ^ key[idx2]
    data_pack.append(rev_seq)

for i in data_pack:
    print("dq 0x" + bytearray(i).hex())
