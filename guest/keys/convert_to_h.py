#!/usr/bin/python

import fileinput

print("#include <stdint.h>\n\nconst uint8_t guest_image_key[] = {")

pub = 0
for line in fileinput.input():
    if  ("pub:" in line):
        pub = 1
    if (pub == 0):
        continue

    if (not line[0].isspace()):
        continue
    line = line.strip()
    print ("\t0x" + line.replace(":",",0x").rstrip("0x"))

print("};")
