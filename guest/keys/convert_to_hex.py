#!/usr/bin/python

import fileinput

pub = 0
for line in fileinput.input():
    if  ("pub:" in line):
        pub = 1
    if (pub == 0):
        continue

    if (not line[0].isspace()):
        continue
    line = line.strip()
    print (line.replace(":",""),end='')
