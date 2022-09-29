#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>

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
#define MAX_ADDR 16

MODULE_LICENSE("GPL");
MODULE_AUTHOR("janikh");
MODULE_DESCRIPTION("Host side kvms crosvm demo module");

static int major;
uint64_t read_paddr;
uint64_t read_size;
char kbuf[PAGE_SIZE * MAX_ADDR];
uint64_t addrs[MAX_ADDR];

static ssize_t device_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
	size_t ret = 0;
	if (*off || len > (PAGE_SIZE * MAX_ADDR))
		return ret;

	ret = copy_to_user((void *)buf, (void *)kbuf, len);
	if (ret) {
		pr_info("copy_to_user error %ld\n", ret);
		ret = -EFAULT;
	} else {
		pr_info("copy_to_user %ld bytes\n", len);
		ret = len;
		*off = 0;
	}

	return ret;
}

static ssize_t device_write(struct file *filp, const char __user *buf, size_t len, loff_t *off)
{
	size_t ret = 0;
	char *kbufptr = kbuf;
	size_t wlen = sizeof(kbuf);
	char *argument;
	const char *delim = " ";
	struct page *page;
	void *vaddr;
	int i;
	char *check;
	size_t rlen = 0;

	if (len < wlen)
		wlen = len;

	memset(addrs, 0, sizeof(addrs));

	if (*off)
		return ret;

	if (copy_from_user(kbuf, buf, wlen))
		return -EFAULT;

	for (i = 0; i < MAX_ADDR; i++) {
		argument = strsep(&kbufptr, delim);
		if (argument == NULL)
			break;
		if (kstrtoull(argument, 16, &addrs[i])) {
			pr_err("64bit hex values only: %s\n", argument);
			addrs[0] = 0;
			break;
		}
	}

	for (i = 0; i < MAX_ADDR; i++) {
		if (!addrs[i])
			break;
		page = phys_to_page(addrs[i]);
		vaddr = page_address(page);
		check = (char *)vaddr;
		pr_info("read from: %llx len: 0x%lx\n", (u_int64_t)vaddr, PAGE_SIZE);
		pr_info("vaddr %x%x%x%x%x%x%x%x\n", check[0], check[1], check[2], check[3], check[4], check[5], check[6], check[7]);
		memcpy((void *)&kbuf[rlen], vaddr, PAGE_SIZE);
		rlen += PAGE_SIZE;
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
