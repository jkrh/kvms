#!/usr/bin/python

import fileinput
import sys

if (len(sys.argv) < 2):
    print("Error")
    exit(1)

found = 0
if (len(sys.argv) > 2):
    print("#include <stdint.h>\n\nconst uint8_t {}[] = {{".format(sys.argv[2]))

for line in sys.stdin:
    if  (sys.argv[1] in line):
        found = 1
        continue
    if (found == 0):
        continue

    if (not line[0].isspace()):
        break
    line = line.strip()
    if (len(sys.argv) == 2):
        print (line.replace(":",""),end='')
    else:
        print ("\t0x" + line.replace(":",",0x").rstrip("0x"))

if (len(sys.argv) > 2):
    print("};")
