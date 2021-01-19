#!/usr/bin/python

import getopt
import time
import os
import re
import signal
import subprocess
import sys
from subprocess import PIPE

# TODO: set these as parameters to the script
pwd = os.getcwd()
KERNEL_DIR=os.path.join(pwd, "linux")
BOOTIMG=os.path.join(pwd, "ubuntu-18.04.3-preinstalled-server-arm64.qcow2")
PLATFORM="virt"

result=0

def title(title):
  print("\n")
  print("#########################")
  print(" module-test: " + title)
  print("#########################")
  print("\n")


def error(message):
  print(message)
  title("ERROR DETECTED, ABORTING");
  result=-1
  raise Exception("timeout")


def set_environment():
  if BOOTIMG and not os.path.exists(BOOTIMG):
    error("BOOTIMG file '%s' is missing" % BOOTIMG)
  if KERNEL_DIR and not os.path.exists(KERNEL_DIR):
    error("KERNEL_DIR dir '%s' is missing" % KERNEL_DIR)

  os.environ['KERNEL_DIR'] = KERNEL_DIR
  os.environ['PLATFORM'] = PLATFORM
  os.environ['BOOTIMG'] = BOOTIMG


def check_prerequisites():
  if PLATFORM != "virt":
    error("only virt platform supported")


def download_bootimg():
  title("download bootimg")
  # TODO

def wait_for_output(process, line, timeout):
  # TODO: we could handle timeout better here
  # now if process does not output anything to
  # stdout we are stuck here, we can handle this
  # in jenkins though
  timeout_time = time.time() + timeout;
  while time.time() < timeout_time:
    output = process.stdout.readline()
    if output:
      print(output.strip())
    if re.search(line,output):
      time.sleep(1)
      return
  error("timeout")


def start_qemu():
  global p_qemu
  title("start ubuntu in qemu")

  p_qemu = subprocess.Popen(["make","run"], stdin=PIPE, stdout=PIPE)
  wait_for_output(p_qemu, '^Ubuntu 18.04.3 LTS ubuntu', 30)

  # give username and password
  p_qemu.stdin.write("ubuntu\n")
  time.sleep(1)
  p_qemu.stdin.write("ubuntu\n")

  # allow external ssh
  p_qemu.stdin.write("./net.sh\n")


def stop_qemu():
  title("stop qemu")
  p_qemu.stdin.write("sudo shutdown -h now\n")
  wait_for_output(p_qemu, 'reboot: Power down', 60);


def ssh_and_start_yocto():
  global p_ssh
  title("ssh and login to yocto")

  hostname=subprocess.check_output("hostname -I | awk '{print $1}'", shell=True).strip()
  p_ssh = subprocess.Popen(["sshpass", "-p", "ubuntu", "ssh", "ubuntu@" + hostname, "-p", "10022", "cd vm && sudo ./run-qemu.sh core-image*"], stdin=PIPE, stdout=PIPE)
  wait_for_output(p_ssh, '^Poky \(Yocto Project Reference Distro\)', 60)

  # give password
  p_ssh.stdin.write("root\n")
  time.sleep(10)

  title("shutdown yocto")
  p_ssh.stdin.write("shutdown -h now\n")
  time.sleep(15)
  #wait_for_output(p_ssh, 'reboot: Power down', 60); TODO: not working


def cleanup():
  title("cleanup")

  if 'p_ssh' in globals():
    if p_ssh.poll() is None:
      result=-10
      print("killing ssh process")
      os.killpg(os.getpgid(p_ssh.pid), signal.SIGINT)
  if 'p_qemu' in globals():
    if p_qemu.poll() is None:
      result=-11
      print("killing qemu process")
      os.killpg(os.getpgid(p_qemu.pid), signal.SIGINT)

def usage():
  print("usage:")
  print("-h, --help        print usage")
  print("-b, --bootimage   assign bootimage (needs parameter)")
  print("-k, --kerneldir   assign kerneldir (needs parameter)")
  print("-y, --yocto       test ssh and yocto (needs parameter: true/false)")
  sys.exit(0)

def main():
  global BOOTIMG
  YOCTO=True

  try:
    opts, args = getopt.getopt(sys.argv[1:], 'b:k:y:h', ['bootimg=', 'kerneldir=', 'yocto=', 'help'])
  except getopt.GetoptError:
    usage()

  for opt, arg in opts:
    if opt in ( '-b', '--bootimage' ):
      BOOTIMG=arg
    if opt in ( '-k', '--kerneldir' ):
      BOOTIMG=arg
    if opt in ( '-y', '--yocto' ):
      YOCTO=((arg == 'true') or (arg == 'True'))
    else:
      usage()

  try:
    set_environment()
    check_prerequisites()
    download_bootimg()
    start_qemu()
    if YOCTO:
      ssh_and_start_yocto()
    stop_qemu()
  finally:
    cleanup()
    sys.exit(result)

if __name__ == "__main__":
    main()
