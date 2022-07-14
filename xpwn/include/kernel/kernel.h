#ifndef KERNEL_H
#define KERNEL_H

#include <abstractfile.h>
#include <patchfinder.h>

#include <xpwn/libxpwn.h>
#include <xpwn/outputstate.h>
#include <xpwn/pwnutil.h>
#include <xpwn/nor_files.h>

int patchKernel(AbstractFile* inFile, AbstractFile* outFile);
int doKernelPatch(StringValue* fileValue, const char* bundlePath, OutputState** state, unsigned int* key, unsigned int* iv, int useMemory);

#define PATCH_NONE              (0)

struct macho_address {
    uint32_t text_buf_base; // buf base
    uint32_t text_base;     // __TEXT vm base
    uint32_t text_size;     // __TEXT vm size
    uint32_t data_base;     // __DATA vm base
    uint32_t data_size;     // __DATA vm size
    uint32_t delta;         // delta (kext_base)
    
    uint32_t last_section;  // __TEXT last
    
    uint32_t text_text_addr;
    uint32_t text_text_size;
    uint32_t text_const_addr;
    uint32_t text_const_size;
    uint32_t text_cstring_addr;
    uint32_t text_cstring_size;
    uint32_t text_os_log_addr;
    uint32_t text_os_log_size;
};

struct helper_offset {
    uint32_t ret0_gadget;
    uint32_t ret1_gadget;
    uint32_t memcmp;
    uint32_t vn_getpath;
    uint32_t vfs_context_current;
    uint32_t vnode_getattr;
    uint32_t vnode_isreg;
};

struct text_offset {
    uint32_t vm_fault_enter;
    uint32_t vm_map_enter;
    uint32_t vm_map_protect;
    uint32_t mac_mount;
    uint32_t csops;
    uint32_t csops2;
    uint32_t pid_check;
    uint32_t convert_port_to_locked_task;
    uint32_t i_can_has_debugger;
};

struct amfi_offset {
    uint32_t i_can_has_debugger_got;
    uint32_t cs_enforcement_got;
    uint32_t vnode_isreg_got;
    uint32_t execve_hook;
};

struct sandbox_offset {
    uint32_t i_can_has_debugger_got;
    uint32_t memset_got;
    uint32_t ops;
    uint32_t sb_evaluate;
};

struct lwvm_offset {
    uint32_t i_can_has_debugger_got;
    uint32_t i_can_has_kernel_configuration_got;
    uint32_t jump;
    uint32_t mapForIO;
};

#endif
