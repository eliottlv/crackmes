#!/usr/bin/env python3

"""
Encrypt an address with a simple XOR on qword.

Arg1 : the address to encrypt.
"""

from os import urandom
from sys import argv

# Data to encrypt
data = list(bytes.fromhex(argv[1][2:]))

# Pad address
if len(data) != 8:
    pad_len = 8 - len(data)
    tmp = [0x00 for i in range(0, pad_len)]
    tmp.extend(data)
    data = tmp

# Key
key = list(urandom(8))

# Print key
result_str = "0x" + bytearray(key).hex()
print(f"key  = {result_str}")


# Results
result = data.copy()

# XOR
for idx, byte in enumerate(result):
    result[idx] = byte ^ key[idx]

result_str = "0x" + bytearray(result).hex()
print(f"addr = {result_str}")
