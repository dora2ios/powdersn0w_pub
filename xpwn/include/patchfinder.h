#ifndef PATCHFINDER_H
#define PATCHFINDER_H

#include <stdint.h>
#include <string.h>

int insn_is_32bit(uint16_t* i);

unsigned int make_b_w(int pos, int tgt);
uint32_t make_bl(int pos, int tgt);

uint32_t find_image_passed_signature(uint32_t region, uint8_t* data, size_t size);
uint32_t find_image_failed_signature(uint32_t region, uint8_t* data, size_t size);
uint32_t buggy_find_csdir_magic(uint32_t region, uint8_t* data, size_t size);

int find_iboot_version(uint8_t* data, size_t size);
char* find_iboot_type(uint8_t* data, size_t size);
uint32_t find_iboot_base(uint8_t* data, size_t size);
uint32_t find_verify_shsh(uint8_t* data, size_t size);
uint32_t find_debug_enabled(uint32_t region, uint8_t* data, size_t size);
uint32_t find_ticket1(uint32_t region, uint8_t* data, size_t size);
uint32_t find_ticket2(uint32_t region, uint8_t* data, size_t size);
uint32_t find_boot_partition(uint32_t region, uint8_t* data, size_t size);
uint32_t find_boot_ramdisk(uint32_t region, uint8_t* data, size_t size);
uint32_t find_release_env_set_whitelist(uint32_t region, uint8_t* data, size_t size);
uint32_t find_whitelist(uint32_t region, uint8_t* data, size_t size);
uint32_t find_sys_setup_default_environment(uint32_t region, uint8_t* data, size_t size);
uint32_t find_boot_args_xref(uint32_t region, uint8_t* data, size_t size);
uint32_t find_boot_args_null_xref(uint32_t region, uint8_t* data, size_t size);
uint32_t find_reliance_str(uint32_t region, uint8_t* data, size_t size);
uint32_t find_go_cmd_handler(uint32_t region, uint8_t* data, size_t size);

int find_xnu_major_version(uint32_t region, uint8_t* kdata, size_t ksize);
int find_xnu_minor_version(uint32_t region, uint8_t* kdata, size_t ksize);

// Helper gadget
uint32_t find_ret0_gadget(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_ret1_gadget(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_vn_getpath(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_memcmp(uint32_t region, uint8_t* kdata, size_t ksize);

uint32_t find_vm_fault_enter_patch(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_vm_map_enter_patch(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_vm_map_protect_patch(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_mount(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_mount_90(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_csops(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_tfp0_patch(uint32_t region, uint8_t* kdata, size_t ksize);

uint32_t find_amfi_execve_ret(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_amfi_cs_enforcement_got(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_amfi_PE_i_can_has_debugger_got(uint32_t region, uint8_t* kdata, size_t ksize);

uint32_t find_PE_i_can_has_kernel_configuration_got(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_lwvm_jump(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_mapForIO(uint32_t region, uint8_t* kdata, size_t ksize);

uint32_t find_sandbox_mac_policy_ops(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_sb_PE_i_can_has_debugger_got(uint32_t region, uint8_t* kdata, size_t ksize, uint32_t ops);

// ios6
uint32_t find_vm_map_enter_patch_ios6(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_vm_map_protect_patch_ios6(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_tfp0_patch_ios6(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_amfi_PE_i_can_has_debugger_got_ios6(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_sb_PE_i_can_has_debugger_got_ios6(uint32_t region, uint8_t* kdata, size_t ksize, uint32_t ops);
uint32_t find_sb_patch(uint32_t region, uint8_t* kdata, size_t ksize);

// ios8
uint32_t find_vm_fault_enter_patch_84(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_vm_map_enter_patch_84(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_vm_map_protect_patch_84(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_mount_84(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_csops_84(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_csops2_84(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_amfi_cs_enforcement_got_84(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_amfi_PE_i_can_has_debugger_got_84(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_sb_PE_i_can_has_debugger_got_84(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_mapForIO_84(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_vn_getpath_84(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_memcmp_84(uint32_t region, uint8_t* kdata, size_t ksize);
#endif
