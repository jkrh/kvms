#! /usr/bin/python3
import subprocess
import sys
import os
from sys import exit

def find_dev(file):
    if file.startswith("/dev/nbd"):
        return file
    file = file.rstrip("/")
    tmp = subprocess.run(["mount","-t","ext4"], stdout=subprocess.PIPE)
    mounts  = tmp.stdout.decode().splitlines()
    s = []
    for mnt in mounts:
        if mnt.startswith("/dev/nbd"):
            x = mnt.split()
            if not file.startswith("/"):
                file = os.getcwd() + "/" + file
            if (file == x[2]):
                return x[0]
    else:
        return ""

def usage():
    print("Usage: qumount.sh <mount point>")

if (len(sys.argv) != 2):
    usage()
    exit()

dev = find_dev(sys.argv[1])
if (len(dev) > 0):
        cmd = "qemu-nbd --disconnect {}".format(dev)
        print(cmd)
        os.system(cmd)
        cmd = "umount {}".format(dev)
        print(cmd)
        os.system(cmd)
