/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/uaccess.h>
#include <linux/fs.h>

#include <../arch/arm64/kvm/hvccall-defines.h>
#include "kvms-test-common.h"

/**
 * @brief kvms test module
 *
 * Usage:
 * Copy the module hvc-t.ko with its dependency kvms-t-common.ko to the target
 * file system.
 *
 * Create device:
 * At the location where the module is copied to:
 * insmod kvms-t-common.ko
 * insmod hvc-t.ko
 * cat /proc/devices |grep kvms (get down major number)
 * mknod "/dev/hvc-t" c <the major number above> 0
 * like : "mknod "/dev/hvc-t" c 510 0"
 *
 * Use device:
 *
 * echo 0x8004 0xbeef > /dev/hvc-t
 * cat /dev/hvc-t
 * rm /dev/hvc-t
 * rmmod hvc-t.ko
 */

#define NAME "hvc-t"
#define MAX_CMD_PARAMS 8

MODULE_LICENSE("GPL");
MODULE_AUTHOR("memyselfandi");
MODULE_DESCRIPTION("KVMS HVC test module");

static int major;
uint64_t datalocation;
uint64_t paddr;
uint64_t vaddr;

char kbuf[128];

static ssize_t device_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
	size_t ret = 0;
	size_t rlen = sizeof(kbuf);

	if (*off == 0) {
		sprintf(kbuf, "read from: %llx len: %lld\n", paddr, vaddr);
		if (copy_to_user(buf, kbuf, rlen)) {
			ret = -EFAULT;
		} else {
			ret = rlen;
			*off = 1;
		}
	}
	return ret;
}

static ssize_t device_write(struct file *filp, const char __user *buf, size_t len, loff_t *off)
{
	size_t ret = 0;
	char *kbufptr = kbuf;
	size_t wlen = sizeof(kbuf);
	int err;
	uint64_t cmd[MAX_CMD_PARAMS];
	char *argument;
	const char *delim = " ";
	int i;

	if (len < wlen)
		wlen = len;

	memset(kbuf, 0, sizeof(kbuf));
	memset(cmd, 0, sizeof(cmd));

	if (*off)
		return ret;

	if (copy_from_user(kbuf, buf, wlen))
		return -EFAULT;

	for (i = 0; i < MAX_CMD_PARAMS; i++) {
		argument = strsep(&kbufptr, delim);
		if (argument == NULL)
			break;
		if (kstrtoull(argument, 16, &cmd[i])) {
			printk(KERN_ERR "64bit hex values only: %s\n", argument);
			cmd[0] = 0;
			break;
		}
	}

	switch (cmd[0]) {
	/*
	 * Host protection support
	 */
	case HYP_HOST_MAP_STAGE1:
	case HYP_HOST_MAP_STAGE2:
	case HYP_HOST_UNMAP_STAGE1:
	case HYP_HOST_UNMAP_STAGE2:
	case HYP_HOST_BOOTSTEP:
	case HYP_HOST_GET_VMID:
	case HYP_HOST_SET_LOCKFLAGS:
	case HYP_HOST_PREPARE_STAGE1:
	case HYP_HOST_PREPARE_STAGE2:

	/*
	 * KVM guest support
	 */
	case HYP_READ_MDCR_EL2:
	case HYP_SET_HYP_TXT:
	case HYP_SET_TPIDR:
	case HYP_INIT_GUEST:
	case HYP_FREE_GUEST:
	case HYP_UPDATE_GUEST_MEMSLOT:
	case HYP_GUEST_MAP_STAGE2:
	case HYP_GUEST_UNMAP_STAGE2:
	case HYP_USER_COPY:
	case HYP_MKYOUNG:
	case HYP_SET_GUEST_MEMORY_OPEN:
	case HYP_SET_GUEST_MEMORY_BLINDED:
	case HYP_MKOLD:
	case HYP_ISYOUNG:
	case HYP_TRANSLATE:
	case HYP_SET_MEMCHUNK:
	case HYP_RELEASE_MEMCHUNK:
	case HYP_GUEST_VCPU_REG_RESET:
	case HYP_GUEST_MEMMAP:
	case HYP_STOP_GUEST:
	case HYP_RESUME_GUEST:
	/*
	 * Misc
	 */
	case HYP_READ_LOG:
	case HYP_SYNC_GPREGS:

	/*
	* Guest specific key support
	*/
	case HYP_GENERATE_KEY:
	case HYP_GET_KEY:
	case HYP_DELETE_KEY:
	case HYP_SAVE_KEY:
	case HYP_LOAD_KEY:
	case HYP_DEFINE_GUEST_ID:

	default:
		/* Just pass the rest to KVMs as they are */
		printk(KERN_INFO "hvc: 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx\n",
			   cmd[0], cmd[1], cmd[2], cmd[3], cmd[4], cmd[5], cmd[6], cmd[7] );
		err = kvms_hyp_call(cmd[0], cmd[1], cmd[2], cmd[3], cmd[4], cmd[5], cmd[6], cmd[7]);
		if (err)
			pr_err("kvm: %s failed: %d\n", __func__, err);
		break;
	}

	ret = wlen;
	*off = 1;
	return ret;
}

static const struct file_operations fops = {
	.owner = THIS_MODULE,
	.read = device_read,
	.write = device_write,
};

static int __init kvms_t_entry(void)
{
	major = register_chrdev(0, NAME, &fops);
	return 0;
}

static void __exit kvms_t_exit(void)
{
	unregister_chrdev(major, NAME);
}

module_init(kvms_t_entry);
module_exit(kvms_t_exit);
