/*#include <stdint.h>*/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <../arch/arm64/kvm/hvccall-defines.h>
#include "kvms-test-common.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("janikh");
MODULE_DESCRIPTION("Guest side kvms crosvm demo module");

extern uintptr_t	_binary_secret_png_start;
extern uintptr_t	_binary_secret_png_end;

#define IMAGE_BASE	((unsigned long)(&_binary_secret_png_start))
#define IMAGE_END	((unsigned long)(&_binary_secret_png_end))

static int __init demo_entry(void)
{
	uint64_t phys, virts = IMAGE_BASE;
	size_t image_size = IMAGE_END - IMAGE_BASE;

	pr_info("%s %s...->\n", __FILE__, __func__);
	pr_info("    Secret start virtual: 0x%llx\n", virts);
	pr_info("    Secret end virtual: 0x%lx\n", IMAGE_END);
	pr_info("    Secret size: 0x%lx dec:%ld\n", image_size, image_size);

	for (virts = IMAGE_BASE; virts < (IMAGE_BASE + image_size); virts += PAGE_SIZE) {
		phys = (uint64_t)virt_to_ipa(virts);
		pr_info("    Secret page ipa: 0x%llx\n", phys);
		phys = kvms_hyp_get(HYP_TRANSLATE, phys);
		pr_info("    Secret page phy: 0x%llx\n", phys);
	}

	return 0;
}

static void __exit demo_exit(void)
{
	pr_info("<-...%s %s\n", __FILE__, __func__);
}

module_init(demo_entry);
module_exit(demo_exit);
