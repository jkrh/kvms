/*#include <stdint.h>*/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <../arch/arm64/kvm/hvccall-defines.h>
#include "kvms-test-common.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("janikh");
MODULE_DESCRIPTION("Guest side kvms crosvm demo module");

extern uintptr_t	_binary_image_png_start;
extern uintptr_t	_binary_image_png_size;
extern uintptr_t	_binary_image_png_end;

#define IMAGE_BASE	((unsigned long)(&_binary_image_png_start))
#define IMAGE_SIZE	((unsigned long)(&_binary_image_png_size))
#define IMAGE_END	((unsigned long)(&_binary_image_png_end))

static int __init demo_entry(void)
{
	uint64_t phys, phye;

	pr_info("%s %s...->\n", __FILE__, __func__);
	pr_info("    Image start virtual: 0x%lx\n", IMAGE_BASE);
	pr_info("    Image end virtual: 0x%lx\n", IMAGE_END);

	phys = (uint64_t)virt_to_phys((void *)IMAGE_BASE);
	phye = (uint64_t)virt_to_phys((void *)IMAGE_END);

	pr_info("    Image start physical: 0x%llx\n", phys);
	pr_info("    Image end physical: 0x%llx\n", phye);

	phys = (uint64_t)virt_to_ipa(IMAGE_BASE);
	phye = (uint64_t)virt_to_ipa(IMAGE_END);

	pr_info("    Image start ipa: 0x%llx\n", phys);
	pr_info("    Image end ipa: 0x%llx\n", phye);

	phys = kvms_hyp_call(HYP_TRANSLATE, phys);
	phye = kvms_hyp_call(HYP_TRANSLATE, phye);

	pr_info("    Image start phy: 0x%llx\n", phys);
	pr_info("    Image end phy: 0x%llx\n", phye);

	return 0;
}

static void __exit demo_exit(void)
{
	pr_info("<-...%s %s\n", __FILE__, __func__);
}

module_init(demo_entry);
module_exit(demo_exit);
