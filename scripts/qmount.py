#! /usr/bin/python3
import subprocess
import sys
from sys import exit
import glob
import time
import os

def wait_for_dev(dev: str, secs: int = 5):
    print("Waiting for {}...".format(dev))
    s_time = time.time()
    while True:
        if time.time() - s_time > secs:
            print("ERROR: {} secs timeout exceeded!".format(secs))
            return False
        if os.path.exists(dev):
            break
        else:
            time.sleep(1)
    return True


def find_free_dev():
    tmp = subprocess.run(["ls -1 /dev/nb*"],  shell=True, stdout=subprocess.PIPE)
    mounts  = tmp.stdout.decode().splitlines()
    s = []
    for mnt in mounts:
        if mnt.endswith("p1"):
            x = mnt.partition("/dev/nbd")
            s.append(x[2][0])

    for i in range(0, 8):
        if not str(i) in s:
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
    cmd =["modprobe", "nbd", "max_part=8"]
    print(" ".join(cmd))
    p = subprocess.run(cmd)
    if p.returncode:
        exit(1)

if (len(dev) > 0):
    cmd = ["qemu-nbd","--connect={}".format(dev), sys.argv[1]]
    print(" ".join(cmd))
    p = subprocess.run(cmd)
    if p.returncode:
        exit(1)

    pdev = "{}p1".format(dev)
    wait_for_dev(pdev)

    cmd = "mount {}p1 {}".format(dev,sys.argv[2])
    print(cmd)
    if os.system(cmd):
        cmd = "qemu-nbd --disconnect {}".format(dev)
        print(cmd)
        os.system(cmd)
