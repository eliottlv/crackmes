#!/usr/bin/env python3

"""
Generate random bytes to insert in code to mislead to disassembler.
Output is formated for "db" storing.

Arg1 : the number of bytes to generate
"""

from os import urandom
from sys import argv

length = int(argv[1])
data = list(urandom(length))
result = ""
for i in data:
    result += "0x" + bytearray([i]).hex() + ","
result = result[:-1]
print(result)
