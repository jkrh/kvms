#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include "../arch/arm64/kvm/hvccall-defines.h"

// compile against host kernel
// insmod demo-h.ko
// cat /proc/devices (get major number)
// mknod "/dev/kvms_host_side_demo" c <the major above> 0
// demodemo
//
// echo 1 > /dev/kvms_host_side_demo
// cat /dev/kvms_host_side_demo
//
// rm /dev/kvms_host_side_demo
// rmmod demo-h.ko

#define NAME "kvms_host_side_demo"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("janikh");
MODULE_DESCRIPTION("Host side kvms crosvm demo module");

static int major;
uint64_t read_paddr;
uint64_t read_size;
char kbuf[128];

static ssize_t device_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
	size_t ret = 0;
	size_t rlen = sizeof(kbuf);

	if (*off == 0) {
		sprintf(kbuf, "read from: %llx len: %lld\n", read_paddr, read_size);
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
	size_t wlen = sizeof(kbuf);
	int cmd;

	if (len < wlen)
		wlen = len;

	memset(kbuf, 0, sizeof(kbuf));

	if (*off == 0) {
		if (copy_from_user(kbuf, buf, wlen)) {
			ret = -EFAULT;
		} else {
			if (kstrtoull(kbuf, 16, &read_size)) {
				pr_info("    only hex values allowed: %s\n", kbuf);
				cmd = 0;
			}
			pr_info("    command: %d\n", cmd);
			switch (cmd) {
			case 1:
			case 2:
			case 3:
				ret = __kvms_hvc_cmd(HYP_HOST_BOOTSTEP, cmd);
				if (ret)
					pr_err("kvm: %s failed: %ld\n", __func__, ret);
				break;
			default:
				break;
			}
			ret = wlen;
			*off = 1;
		}
	}
	return ret;
}

static const struct file_operations fops = {
	.owner = THIS_MODULE,
	.read = device_read,
	.write = device_write,
};

static int __init demo_entry(void)
{
	major = register_chrdev(0, NAME, &fops);
	return 0;
}

static void __exit demo_exit(void)
{
	unregister_chrdev(major, NAME);
}

module_init(demo_entry);
module_exit(demo_exit);
