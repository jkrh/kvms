// SPDX-License-Identifier: GPL-2.0-only
/*
 * Hypervisor call module for userspace
 *
 * Copyright (C) 2021 Digital14 Ltd.
 *
 * Authors:
 * Konsta Karsisto <konsta.karsisto@gmail.com>
 *
 * File: hyp-drv.c
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <asm-generic/bug.h>
#include <asm-generic/ioctls.h>
#include <linux/mm.h>
#include <asm/memory.h>
#include <linux/slab.h>
#include "hvccall-defines.h"
#include "kaddr.h"
#include "hyp-drv.h"

MODULE_DESCRIPTION("Hypervisor call module for userspace");
MODULE_LICENSE("GPL v2");

#define DEVICE_NAME "hyp-drv"
#define ADDR_MASK 0xFFFFFFFFFFFF
#define ROUND_DOWN(N,M) ((N) & ~((M) - 1))
#define MK_HMR(START, END, PROT) (struct hypdrv_mem_region)\
	{PAGE_ALIGN((u64)(START)), PAGE_ALIGN((u64)(END)), PROT}
#define BUG_ON_NONALIGNED(START) \
	BUILD_BUG_ON(!PAGE_ALIGNED(START));

static int major;
static int dopen;

static u64 kaddr_to_phys(u64 kaddr)
{
	return virt_to_phys((void *)kaddr);
}

#define __asmeq(x, y)  ".ifnc " x "," y " ; .err ; .endif\n\t"

static noinline int
call_hyp(u64 function_id, u64 arg0, u64 arg1, u64 arg2, u64 arg3)
{
	register u64 reg0 asm ("x0") = function_id;
	register u64 reg1 asm ("x1") = arg0;
	register u64 reg2 asm ("x2") = arg1;
	register u64 reg3 asm ("x3") = arg2;
	register u64 reg4 asm ("x4") = arg3;

	__asm__ __volatile__ (
		__asmeq("%0", "x0")
		__asmeq("%1", "x1")
		__asmeq("%2", "x2")
		__asmeq("%3", "x3")
		__asmeq("%4", "x4")
		"hvc	#0\n"
		: "+r"(reg0)
		: "r"(reg1), "r"(reg2), "r"(reg3), "r"(reg4)
		: "memory");

	return reg0;
}

/* Not supported in the virt environment currently:
static noinline int
_smc(u64 function_id, u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4)
{
        register int reg0 asm ("x0") = function_id;
        register u64 reg1 asm ("x1") = arg0;
        register u64 reg2 asm ("x2") = arg1;
        register u64 reg3 asm ("x3") = arg2;
        register u64 reg4 asm ("x4") = arg3;
        register u64 reg5 asm ("x5") = arg4;

        __asm__ __volatile__ (
                __asmeq("%0", "x0")
                __asmeq("%1", "x1")
                __asmeq("%2", "x2")
                __asmeq("%3", "x3")
                __asmeq("%4", "x4")
                __asmeq("%5", "x5")
                "smc    #0\n"
                : "+r"(reg0)
                : "r"(reg1), "r"(reg2), "r"(reg3), "r"(reg4), "r"(reg5)
                : "memory");

        return reg0;
}

static int is_kvms(void)
{
	int ret;

	ret = _smc(0xFFFFFFFFE, 0, 0, 0, 0, 0);
	if (ret != 0x99)
		ret = 0;

	return ret;
}
*/


static ssize_t
do_host_map(struct hypdrv_mem_region *reg)
{
	u64 section_start;
	u64 section_end;
	u64 size, prot;
	int ret;

	section_start = kaddr_to_phys(reg->start) & ADDR_MASK;
	section_end   = kaddr_to_phys(reg->end) & ADDR_MASK;
	size = ROUND_DOWN(reg->end - reg->start, 0x1000);
	prot = reg->prot;

#ifdef DEBUG
        pr_info("HYPDRV %s: %llx %llx %llx [ %llx %llx %llx ]\n", __func__,
                reg->start, reg->end, prot, section_start, section_end, size);
#endif

	ret = call_hyp(HYP_HOST_MAP_STAGE2, section_start, section_start,
		       size, prot | s2_wb);

	return ret;
}

static int
do_hvc_lock(void)
{
	return call_hyp(HYP_HOST_SET_LOCKFLAGS,
			HOST_STAGE1_LOCK |
			HOST_STAGE2_LOCK |
			HOST_KVM_CALL_LOCK,
			0 , 0, 0);
}

static ssize_t
kernel_lock(void)
{
	struct hypdrv_mem_region reg;
	int err = -ENODEV;

	BUG_ON_NONALIGNED(_text__addr);
	BUG_ON_NONALIGNED(_etext__addr);
	BUG_ON_NONALIGNED(_data__addr);
	BUG_ON_NONALIGNED(__start_rodata__addr);
	BUG_ON_NONALIGNED(vdso_start__addr);
	BUG_ON_NONALIGNED(vdso_end__addr);

	preempt_disable();
	local_irq_disable();

	/*
	if (!is_kvms()) {
		pr_err("HYPDRV: hyp mode not available?");
		goto out;
	}
	*/

	/* kernel text section */
	reg = MK_HMR(_text__addr, _etext__addr, HYPDRV_KERNEL_EXEC);
	err = do_host_map(&reg);
	if (err)
		goto out;

	/* kernel data */
	reg = MK_HMR(_data__addr, __bss_stop__addr, HYPDRV_PAGE_KERNEL);
	err = do_host_map(&reg);
	if (err)
		goto out;

	/* vdso */
	reg = MK_HMR(vdso_start__addr, vdso_end__addr, HYPDRV_PAGE_VDSO);
	err = do_host_map(&reg);
	if (err)
		goto out;

	/* rodata */
	reg = MK_HMR(__start_rodata__addr, vdso_start__addr,
		     HYPDRV_PAGE_KERNEL_RO);
	err = do_host_map(&reg);

	if (err)
		goto out;

	reg = MK_HMR(vdso_end__addr, __end_rodata__addr, HYPDRV_PAGE_KERNEL_RO);
	err = do_host_map(&reg);
	if (err)
		goto out;

	err = do_hvc_lock();

out:
	local_irq_enable();
	preempt_enable();


	if (err)
		pr_err( "HYPDRV %s: return %d\n", __func__, err);
#ifdef DEBUG
	else
		pr_info("HYPDRV %s: return %d\n", __func__, err);
#endif

	return err;
}

static int device_open(struct inode *inode, struct file *filp)
{
	if (dopen)
		return -EBUSY;

	dopen = 1;
	return 0;
}

static int device_release(struct inode *inode, struct file *filp)
{
	dopen = 0;

	return 0;
}

static ssize_t
device_read(struct file *filp, char *buffer, size_t length, loff_t *off)
{
	return -ENOTSUPP;
}

static ssize_t
device_write(struct file *filp, const char *buf, size_t len, loff_t *off)
{
	ssize_t res;
	static int locked;

	if (locked)
		return len;

	res = kernel_lock();
	if (res)
		return res;
	locked = 1;

	return len;
}

#ifdef DEBUG
static ssize_t
do_write(struct hypdrv_mem_region *reg)
{
	u64 *section_start;
	u64 *section_end;
	u64 *pos;

	section_start = (u64 *) kaddr_to_phys(reg->start);
	section_end   = (u64 *) kaddr_to_phys(reg->end);

	for (pos = section_start; pos < section_end; pos++)
		*pos = 0xdeadbeef;

	return 0;
}
#endif

static ssize_t
do_savekeys(void __user *argp)
{
	uint64_t ret = -ENODATA;
	struct encrypted_keys *p;
	u64 len = 1024;
	uint8_t guest_id[32] = "dummy name";

	p = kmalloc(sizeof(struct encrypted_keys), GFP_KERNEL);
	if (!p)
		return -ENOMEM;
	ret = copy_from_user(p, argp, sizeof(struct encrypted_keys));
	if (ret)
		return -EIO;
	/* FIXME:
	 * Current implementation requires that kernel gives an unique value
	 * for each VM. Unique value should be generated secure way.
	 */
	ret = call_hyp(HYP_DEFINE_GUEST_ID, p->vmid,
		      (u64) &guest_id, (u64) sizeof(guest_id), 0);
	if (ret)
		return ret;



	p->len = sizeof(p->buf);
	ret = call_hyp(HYP_SAVE_KEYS, p->vmid,
		      (u64) p->buf, (u64) &len, 0);
	p->len = (u32) len;
	ret = copy_to_user(argp, p, sizeof(struct encrypted_keys));
	if (ret)
		return ret;
	kfree(p);
	return 0;

}

static ssize_t
do_loadkeys(void __user *argp)
{
	uint64_t ret = -ENODATA;
	struct encrypted_keys *p;
	uint8_t guest_id[] = "dummy name";

	p = kmalloc(sizeof(struct encrypted_keys), GFP_KERNEL);
	if (!p)
		return -ENOMEM;
	ret = copy_from_user(p, argp, sizeof(struct encrypted_keys));
	if (ret)
		return -EIO;

	/* FIXME:
	 * Current implementation requires that kernel gives an unique value
	 * for each VM. Unique value should be generated secure way.
	 */
	ret = call_hyp(HYP_DEFINE_GUEST_ID, p->vmid,
		      (u64) &guest_id, (u64) sizeof(guest_id), 0);
	if (ret)
		return ret;

	ret = call_hyp(HYP_LOAD_KEYS, p->vmid, (u64) &p->buf, (u64) p->len, 0);
	if (ret)
		return ret;

	kfree(p);
	return 0;
}

static ssize_t
do_keygen(void __user *argp)
{
	struct guest_key gkeys;
	uint64_t ret;
	u32 bsize = 32;

	ret = copy_from_user(&gkeys, argp, sizeof(struct guest_key));
	if (ret)
		return -EIO;

	ret = call_hyp(HYP_GENERATE_KEY,
		      (u64) &gkeys.key, (u64) &bsize, 1,
		      (u64)&gkeys.name);
	if (ret)
		return ret;

	ret = copy_to_user(argp, &gkeys, sizeof(struct guest_key));
	if (ret)
		return ret;

	return 0;

}

static ssize_t
do_getkey(void __user *argp)
{
	struct guest_key gkeys;
	uint64_t ret;
	u32 bsize = 32;

	ret = copy_from_user(&gkeys, argp, sizeof(struct guest_key));
	if (ret)
		return -EIO;

	ret = call_hyp(HYP_GET_KEY, (u64) &gkeys.key, (u64) &bsize, 1,
		      (u64) &gkeys.name);
	if (ret)
		return ret;

	ret = copy_to_user(argp, &gkeys, sizeof(struct guest_key));
	if (ret)
		return -EIO;

	return 0;
}

static ssize_t
do_read(void __user *argp)
{
	struct log_frag log = { 0 };
	uint64_t res, ret;
	int n;

	res = call_hyp(HYPDRV_READ_LOG, 0, 0, 0, 0);

	n = res & 0xFF;
	if (n == 0 || n > 7)
		return -ENODATA;

	log.frag = res;
	ret = copy_to_user(argp, &log, sizeof(log));

	return ret;
}

int get_region(struct hypdrv_mem_region *reg, void __user *argp)
{
	int ret = 0;

	ret = copy_from_user(reg, argp, sizeof(struct hypdrv_mem_region));

	return ret;
}

static long
device_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct hypdrv_mem_region reg;
	void __user *argp = (void __user *) arg;
	int ret = -ENOTSUPP;

	switch (cmd) {
	case HYPDRV_KERNEL_MMAP:
		ret = get_region(&reg, argp);
		if (ret == 0)
			return do_host_map(&reg);
		break;
#ifdef DEBUG
	case HYPDRV_KERNEL_WRITE:
		ret = get_region(&reg, argp);
		if (ret == 0)
			return do_write(&reg);
		break;
#endif
	case HYPDRV_KERNEL_LOCK:
		ret = kernel_lock();
		break;
	case HYPDRV_READ_LOG:
		ret = do_read(argp);
		break;
	case HYPDRV_GENERATE_KEY:
		ret =  do_keygen(argp);
		break;
	case HYPDRV_READ_KEY:
		ret =  do_getkey(argp);
		break;
	case HYPDRV_SAVE_KEYS:
		ret =  do_savekeys(argp);
		break;
	case HYPDRV_LOAD_KEYS:
		ret =  do_loadkeys(argp);
		break;
	case TCGETS:
#ifdef DEBUG
		pr_info("HYPDRV: not a TTY\n");
#endif
		ret = -ENOTSUPP;
		break;
	default:
		WARN(1, "HYPDRV: unknown ioctl: 0x%x\n", cmd);
	}

	return ret;
}

static const struct file_operations fops = {
	.read = device_read,
	.write = device_write,
	.open = device_open,
	.release = device_release,
	.unlocked_ioctl = device_ioctl,
};

int init_module(void)
{
	pr_info("HYPDRV hypervisor driver\n");

	major = register_chrdev(0, DEVICE_NAME, &fops);

	if (major < 0) {
		pr_err("HYPDRV: register_chrdev failed with %d\n", major);
		return major;
	}
	pr_info("HYPDRV mknod /dev/%s c %d 0\n", DEVICE_NAME, major);

	return 0;
}

void cleanup_module(void)
{
	if (major > 0)
		unregister_chrdev(major, DEVICE_NAME);
	major = 0;
}
