#! /usr/bin/python3
import subprocess
import sys
import os
from sys import exit
import glob

def find_free_dev():
    tmp = subprocess.run(["mount","-t","ext4"], stdout=subprocess.PIPE)
    mounts  = tmp.stdout.decode().splitlines()
    s = []
    for mnt in mounts:
        if mnt.startswith("/dev/nbd"):
            x = mnt.partition("/dev/nbd")
            s.append(x[2][0])

    for i in range(0, 8):
         if  not str(i) in s:
             return "/dev/nbd{}".format(i)
    else:
        return ""

def usage():
    print("Usage: qmount.sh <qcow2 file> <mount point> ")

if (len(sys.argv) != 3):
    usage()
    exit(1)

dev = find_free_dev()
if not dev in glob.glob("/dev/nbd[0-8]"):
    cmd ="modprobe nbd max_part=8"
    print(cmd)
    if os.system(cmd):
        exit(1)

if (len(dev) > 0):
    cmd = "qemu-nbd --connect={} {}".format(dev, sys.argv[1])
    print(cmd)
    if os.system(cmd):
        exit(1)

    cmd = "mount {}p1 {}".format(dev,sys.argv[2])
    print(cmd)
    if os.system(cmd):
        cmd = "qemu-nbd --disconnect {}".format(dev)
        print(cmd)
        os.system(cmd)
