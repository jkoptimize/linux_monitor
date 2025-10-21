#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

#ifdef CONFIG_UNWINDER_ORC
#include <asm/orc_header.h>
ORC_HEADER;
#endif

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x4c9d28b0, "phys_base" },
	{ 0x40a9b349, "vzalloc" },
	{ 0xea82d349, "hrtimer_init" },
	{ 0xc0b7c197, "hrtimer_start_range_ns" },
	{ 0x7e5ca504, "misc_register" },
	{ 0x122c3a7e, "_printk" },
	{ 0x102fe6de, "hrtimer_cancel" },
	{ 0x3bde721b, "misc_deregister" },
	{ 0x999e8297, "vfree" },
	{ 0x10017aa5, "kernel_cpustat" },
	{ 0x5a5a2271, "__cpu_online_mask" },
	{ 0x656e4a6e, "snprintf" },
	{ 0xb19a5453, "__per_cpu_offset" },
	{ 0x65487097, "__x86_indirect_thunk_rax" },
	{ 0x135bb7ec, "hrtimer_forward" },
	{ 0x87a21cb3, "__ubsan_handle_out_of_bounds" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x7cd8d75e, "page_offset_base" },
	{ 0xc968250a, "remap_pfn_range" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0xe2fd41e5, "module_layout" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "1307FF6E8233956D08F3B26");
