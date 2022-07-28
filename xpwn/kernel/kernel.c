#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>

#include <mach-o/loader.h>

#include <abstractfile.h>
#include <patchfinder.h>
#include <xpwn/nor_files.h>

#include <kernel/kernel.h>
#include <patchfinder.h>
#include <mac.h>
#include <sb_payload.h>

#define FLAG_FIND   (1 << 1)
#define FLAG_GET    (1 << 2)
#define FLAG_SET    (1 << 3)
#define FLAG_PATCH  (1 << 4)

const char* ERRLOG(int flag) {
    
    if(flag & FLAG_FIND)
        return "find";
    if(flag & FLAG_GET)
        return "get";
    if(flag & FLAG_SET)
        return "set";
    if(flag & FLAG_PATCH)
        return "patch";
    
    return "unknown";
}

static bool debug_enabled = true;
#define ERROR(x, ...)       do { printf("\x1b[31m"x"\x1b[39m\n", ##__VA_ARGS__); } while(0)
#define DEBUGLOG(x, ...)    do { if(debug_enabled) printf("\x1b[34m"x"\x1b[39m\n", ##__VA_ARGS__); } while(0)
#define LOG(x, ...)         do { printf("\x1b[32m"x"\x1b[39m\n", ##__VA_ARGS__); } while(0)
#define FAIL(x,y, ...)      do { printf("\x1b[31m[%s] ERROR: failed to %s "y"\x1b[39m\n", __FUNCTION__, ERRLOG(x), ##__VA_ARGS__); } while(0)

static uint32_t text_base = 0;
static size_t kernel_size = 0;

static int majorVer = 0;
static int minorVer = 0;

__unused static int write8(void* buf, size_t bufsize, uint32_t addr, uint8_t val)
{
    if(addr+1 > bufsize) {
        ERROR("[%s] overflow!", __FUNCTION__);
        return -1;
    }
    *(uint8_t*)(buf + addr) = val;
    return 0;
}

__unused static int write16(void* buf, size_t bufsize, uint32_t addr, uint16_t val)
{
    if(addr+2 > bufsize) {
        ERROR("[%s] overflow!", __FUNCTION__);
        return -1;
    }
    *(uint16_t*)(buf + addr) = val;
    return 0;
}

__unused static int write32(void* buf, size_t bufsize, uint32_t addr, uint32_t val)
{
    if(addr+4 > bufsize) {
        ERROR("[%s] overflow!", __FUNCTION__);
        return -1;
    }
    *(uint32_t*)(buf + addr) = val;
    return 0;
}

static int init_kernel(unsigned char* buf, struct macho_address **addr)
{
    struct macho_address *kaddr = (struct macho_address *)malloc(sizeof(struct macho_address));
    if(!kaddr) {
        ERROR("[%s] failed to allocate buffer!", __FUNCTION__);
        goto end;
    }
    memset(kaddr, '\0', sizeof(struct macho_address));
    
    int i = 0;
    __unused uint32_t max = 0;
    __unused uint32_t min = -1;
    
    const struct mach_header *hdr = (struct mach_header *)buf;
    DEBUGLOG("[%s] found magic: %x", __FUNCTION__, hdr->magic);
    if(hdr->magic != MH_MAGIC) {
        ERROR("[%s] unkown magic!", __FUNCTION__);
        goto end;
    }
    kaddr->text_buf_base = (uintptr_t)hdr - (uintptr_t)buf;
    
    
    const unsigned char *q;
    q = (unsigned char*)hdr + sizeof(struct mach_header);
    
    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SEGMENT) {
            const struct segment_command *seg = (struct segment_command *)q;
            if (min > seg->vmaddr) {
                min = seg->vmaddr;
            }
            if (max < seg->vmaddr + seg->vmsize) {
                max = seg->vmaddr + seg->vmsize;
            }
            if (!strcmp(seg->segname, "__TEXT")) {
                kaddr->text_base = seg->vmaddr;
                kaddr->text_size = seg->vmsize;
                
                const struct section *sec = (struct section *)(seg + 1);
                for (uint32_t j = 0; j < seg->nsects; j++) {
                    if (!strcmp(sec[j].sectname, "__text")) {
                        kaddr->text_text_addr = sec[j].addr;
                        kaddr->text_text_size = sec[j].size;
                    } else if (!strcmp(sec[j].sectname, "__const")) {
                        kaddr->text_const_addr = sec[j].addr;
                        kaddr->text_const_size = sec[j].size;
                    } else if (!strcmp(sec[j].sectname, "__cstring")) {
                        kaddr->text_cstring_addr = sec[j].addr;
                        kaddr->text_cstring_size = sec[j].size;
                    } else if (!strcmp(sec[j].sectname, "__os_log")) {
                        kaddr->text_os_log_addr = sec[j].addr;
                        kaddr->text_os_log_size = sec[j].size;
                    }
                }
                
            } else if (!strcmp(seg->segname, "__DATA")) {
                kaddr->data_base = seg->vmaddr;
                kaddr->data_size = seg->vmsize;
            }
            
            DEBUGLOG("[%s] MEM: %08x - %08x: %s%s%s/%s%s%s %s",
                     __FUNCTION__,
                     seg->vmaddr,
                     seg->vmaddr + seg->vmsize,
                     (seg->maxprot & 1<<0) ? "r":"-",
                     (seg->maxprot & 1<<1) ? "w":"-",
                     (seg->maxprot & 1<<2) ? "x":"-",
                     (seg->initprot & 1<<0) ? "r":"-",
                     (seg->initprot & 1<<1) ? "w":"-",
                     (seg->initprot & 1<<2) ? "x":"-",
                     seg->segname);
            
        }
        q = q + cmd->cmdsize;
    }
    kernel_size = max - min; // unused..?
    text_base = kaddr->text_base;
    
    {
        // search __TEXT free area
        uint32_t last_section = 0;
        uint32_t j = 1;
        uint32_t text_last = kaddr->text_base + kaddr->text_size;
        DEBUGLOG("[%s] text_last: %08x", __FUNCTION__, text_last);
        
        if(kaddr->data_base == text_last) {
            for (int i = 0; i < 3/*4*/; i++) {
                if(i==0) {
                    DEBUGLOG("[%s] text_addr: %08x, size: %08x", __FUNCTION__, kaddr->text_text_addr, kaddr->text_text_size);
                    j = kaddr->text_text_addr + kaddr->text_text_size;
                }
                if(i==1) {
                    DEBUGLOG("[%s] const_addr: %08x, size: %08x", __FUNCTION__, kaddr->text_const_addr, kaddr->text_const_size);
                    j = kaddr->text_const_addr + kaddr->text_const_size;
                }
                if(i==2) {
                    DEBUGLOG("[%s] cstring_addr: %08x, size: %08x", __FUNCTION__, kaddr->text_cstring_addr, kaddr->text_cstring_size);
                    j = kaddr->text_cstring_addr + kaddr->text_cstring_size;
                }
                //if(i==3) {
                //    DEBUGLOG("[%s] os_log_addr: %08x, size: %08x", __FUNCTION__, kaddr->text_os_log_addr, kaddr->text_os_log_size);
                //    j = kaddr->text_os_log_addr + kaddr->text_os_log_size;
                //}
                if(j > last_section) last_section = j;
                DEBUGLOG("[%s] %d %08x - %08x", __FUNCTION__, i, last_section, j);
            }
            
            if(text_base > last_section) {
                ERROR("[%s] wtf?!", __FUNCTION__);
                goto end;
            }
            
            if(text_last < last_section+0x100) {
                ERROR("[%s] ayyyy", __FUNCTION__);
                if(text_last < last_section+0xE0) {
                    ERROR("[%s] wtf1?!", __FUNCTION__);
                    goto end;
                } else {
                    last_section += 0xE0;
                    last_section = (last_section & ~0xDF);
                }
            } else {
                last_section += 0x100;
                last_section = (last_section & ~0xFF);
            }
            DEBUGLOG("[%s] __TEXT last: %08x", __FUNCTION__, last_section);
            
        } else {
            ERROR("[%s] wtf2?!", __FUNCTION__);
            goto end;
        }
        kaddr->last_section = last_section;
    }
    

    majorVer = find_xnu_major_version(text_base, buf, kaddr->text_size);
    minorVer = find_xnu_minor_version(text_base, buf, kaddr->text_size);
    
    if(!majorVer)
        goto end;
    LOG("[%s] xnu-%d.%d", __FUNCTION__, majorVer, minorVer);
    
    *addr = kaddr;
    
    return 0;
    
end:
    if(kaddr)
        free((void *)kaddr);
    return -1;
}

static int init_kext(unsigned char* buf, size_t size, const char* ident, struct macho_address **addr)
{
    struct macho_address *kaddr = (struct macho_address *)malloc(sizeof(struct macho_address));
    if(!kaddr) {
        ERROR("[%s] failed to allocate buffer!", __FUNCTION__);
        goto end;
    }
    
    memset(kaddr, '\0', sizeof(struct macho_address));
    
    int i = 0;
    uint8_t* kextBase = memmem(buf, size, ident, strlen(ident));
    if(!kextBase)
        goto end;
    
    uint32_t j = (uintptr_t)kextBase - (uintptr_t)buf;
    
    while(i<j)
    {
        if(*(uint32_t*)kextBase == MH_MAGIC)
            break;
        kextBase -= 1;
        i += 4;
    }
    
    const struct mach_header *hdr = (struct mach_header *)kextBase;
    DEBUGLOG("[%s] found KEXT(%s) magic: %x", __FUNCTION__, ident, hdr->magic);
    if(hdr->magic != MH_MAGIC) {
        ERROR("[%s] unkown magic!", __FUNCTION__);
        goto end;
    }
    kaddr->text_buf_base = (uintptr_t)hdr - (uintptr_t)buf;
    
    const unsigned char *q;
    q = (unsigned char*)hdr + sizeof(struct mach_header);
    
    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SEGMENT) {
            const struct segment_command *seg = (struct segment_command *)q;
            if (!strcmp(seg->segname, "__TEXT")) {
                kaddr->text_base = seg->vmaddr;
                kaddr->text_size = seg->vmsize;
            } else if (!strcmp(seg->segname, "__DATA")) {
                kaddr->data_base = seg->vmaddr;
                kaddr->data_size = seg->vmsize;
            }
            
            DEBUGLOG("[%s] MEM: %08x - %08x: %s%s%s/%s%s%s %s",
                     __FUNCTION__,
                     seg->vmaddr,
                     seg->vmaddr + seg->vmsize,
                     (seg->maxprot & 1<<0) ? "r":"-",
                     (seg->maxprot & 1<<1) ? "w":"-",
                     (seg->maxprot & 1<<2) ? "x":"-",
                     (seg->initprot & 1<<0) ? "r":"-",
                     (seg->initprot & 1<<1) ? "w":"-",
                     (seg->initprot & 1<<2) ? "x":"-",
                     seg->segname);
            
        }
        q = q + cmd->cmdsize;
    }
    
    kaddr->delta = kaddr->text_base - text_base - kaddr->text_buf_base;
    
    *addr = kaddr;
    
    return 0;
end:
    if(kaddr)
        free((void *)kaddr);
    return -1;
}

static int find_helper_offset(unsigned char* buf, struct macho_address *kaddr, struct helper_offset **helperOffset)
{
    struct helper_offset *offset = (struct helper_offset *)malloc(sizeof(struct helper_offset));
    if(!offset) {
        ERROR("[%s] failed to allocate buffer!", __FUNCTION__);
        goto end;
    }
    
    memset(offset, '\0', sizeof(struct helper_offset));
    
    offset->ret0_gadget = find_ret0_gadget(kaddr->text_base, buf, kaddr->text_size);
    if(!offset->ret0_gadget) {
        FAIL(FLAG_FIND, "ret0_gadget");
        goto end;
    }
    offset->ret0_gadget += kaddr->text_base;
    LOG("[%s] %08x: ret0_gadget", __FUNCTION__, offset->ret0_gadget);
    
    offset->ret1_gadget = find_ret1_gadget(kaddr->text_base, buf, kaddr->text_size);
    if(!offset->ret1_gadget) {
        FAIL(FLAG_FIND, "ret1_gadget");
        goto end;
    }
    offset->ret1_gadget += kaddr->text_base;
    LOG("[%s] %08x: ret1_gadget", __FUNCTION__, offset->ret1_gadget);
    
    if(majorVer == 2107) {
        offset->vn_getpath = find_vn_getpath(kaddr->text_base, buf, kaddr->text_size);
        if(!offset->vn_getpath) {
            FAIL(FLAG_FIND, "vn_getpath");
            goto end;
        }
        LOG("[%s] %08x: vn_getpath", __FUNCTION__, offset->vn_getpath);
        offset->memcmp = find_memcmp(kaddr->text_base, buf, kaddr->text_size);
        if(!offset->memcmp) {
            FAIL(FLAG_FIND, "memcmp");
            goto end;
        }
        LOG("[%s] %08x: memcmp", __FUNCTION__, offset->memcmp);
    } else if(majorVer == 2784 || majorVer == 2783) {
        offset->vn_getpath = find_vn_getpath_84(kaddr->text_base, buf, kaddr->text_size);
        if(!offset->vn_getpath) {
            FAIL(FLAG_FIND, "vn_getpath");
            goto end;
        }
        LOG("[%s] %08x: vn_getpath", __FUNCTION__, offset->vn_getpath);
        offset->memcmp = find_memcmp_84(kaddr->text_base, buf, kaddr->text_size);
        if(!offset->memcmp) {
            FAIL(FLAG_FIND, "memcmp");
            goto end;
        }
        LOG("[%s] %08x: memcmp", __FUNCTION__, offset->memcmp);
    }
    
    *helperOffset = offset;
    return 0;
end:
    if(offset)
        free((void *)offset);
    return -1;
}

static int find_text_offset(unsigned char* buf, struct macho_address *addr, struct text_offset **textOffset)
{
    struct text_offset *offset = (struct text_offset *)malloc(sizeof(struct text_offset));
    if(!offset) {
        ERROR("[%s] failed to allocate buffer!", __FUNCTION__);
        goto end;
    }
    
    memset(offset, '\0', sizeof(struct text_offset));
    
    if(majorVer == 3248) {
        // ios 9.x
        if(!(offset->vm_fault_enter = find_vm_fault_enter_patch(addr->text_base, buf, addr->text_size))) {
            FAIL(FLAG_FIND, "vm_fault_enter");
            goto end;
        }
        LOG("[%s] %08x: vm_fault_enter", __FUNCTION__, offset->vm_fault_enter + addr->text_base);
        
        if(!(offset->vm_map_enter = find_vm_map_enter_patch(addr->text_base, buf, addr->text_size))) {
            FAIL(FLAG_FIND, "vm_map_enter");
            goto end;
        }
        LOG("[%s] %08x: vm_map_enter", __FUNCTION__, offset->vm_map_enter + addr->text_base);
        
        if(!(offset->vm_map_protect = find_vm_map_protect_patch(addr->text_base, buf, addr->text_size))) {
            FAIL(FLAG_FIND, "vm_map_protect");
            goto end;
        }
        LOG("[%s] %08x: vm_map_protect", __FUNCTION__, offset->vm_map_protect + addr->text_base);
        
        if(minorVer == 1) {
            if(!(offset->mac_mount = find_mount_90(addr->text_base, buf, addr->text_size))) {
                FAIL(FLAG_FIND, "mac_mount_90");
                goto end;
            }
        } else {
            if(!(offset->mac_mount = find_mount(addr->text_base, buf, addr->text_size))) {
                FAIL(FLAG_FIND, "mac_mount");
                goto end;
            }
        }
        LOG("[%s] %08x: mac_mount", __FUNCTION__, offset->mac_mount + addr->text_base);
        
        if(!(offset->csops = find_csops(addr->text_base, buf, addr->text_size))) {
            FAIL(FLAG_FIND, "csops");
            goto end;
        }
        LOG("[%s] %08x: csops", __FUNCTION__, offset->csops + addr->text_base);
        
        if(!(offset->pid_check = find_tfp0_patch(addr->text_base, buf, addr->text_size))) {
            FAIL(FLAG_FIND, "task_for_pid");
            goto end;
        }
        LOG("[%s] %08x: pid_check", __FUNCTION__, offset->pid_check + addr->text_base);
        
    } else if(majorVer == 2107) {
        // ios 6.x
        if(!(offset->vm_map_enter = find_vm_map_enter_patch_ios6(addr->text_base, buf, addr->text_size))) {
            FAIL(FLAG_FIND, "vm_map_enter");
            goto end;
        }
        LOG("[%s] %08x: vm_map_enter", __FUNCTION__, offset->vm_map_enter + addr->text_base);
        
        if(!(offset->vm_map_protect = find_vm_map_protect_patch_ios6(addr->text_base, buf, addr->text_size))) {
            FAIL(FLAG_FIND, "vm_map_protect");
            goto end;
        }
        LOG("[%s] %08x: vm_map_protect", __FUNCTION__, offset->vm_map_protect + addr->text_base);
        
        if(!(offset->pid_check = find_tfp0_patch_ios6(addr->text_base, buf, addr->text_size))) {
            FAIL(FLAG_FIND, "task_for_pid");
            goto end;
        }
        LOG("[%s] %08x: pid_check", __FUNCTION__, offset->pid_check + addr->text_base);
        
    } else if(majorVer == 2784 || majorVer == 2783) {
        if(!(offset->vm_fault_enter = find_vm_fault_enter_patch_84(addr->text_base, buf, addr->text_size))) {
            FAIL(FLAG_FIND, "vm_fault_enter");
            goto end;
        }
        LOG("[%s] %08x: vm_fault_enter", __FUNCTION__, offset->vm_fault_enter + addr->text_base);
        
        if(!(offset->vm_map_enter = find_vm_map_enter_patch_84(addr->text_base, buf, addr->text_size))) {
            FAIL(FLAG_FIND, "vm_map_enter");
            goto end;
        }
        LOG("[%s] %08x: vm_map_enter", __FUNCTION__, offset->vm_map_enter + addr->text_base);
        
        if(!(offset->vm_map_protect = find_vm_map_protect_patch_84(addr->text_base, buf, addr->text_size))) {
            FAIL(FLAG_FIND, "vm_map_protect");
            goto end;
        }
        LOG("[%s] %08x: vm_map_protect", __FUNCTION__, offset->vm_map_protect + addr->text_base);
        
        if(!(offset->mac_mount = find_mount_84(addr->text_base, buf, addr->text_size))) {
            FAIL(FLAG_FIND, "mac_mount");
            goto end;
        }
        LOG("[%s] %08x: mac_mount", __FUNCTION__, offset->mac_mount + addr->text_base);
        
        if(!(offset->csops = find_csops_84(addr->text_base, buf, addr->text_size))) {
            FAIL(FLAG_FIND, "csops");
            goto end;
        }
        LOG("[%s] %08x: csops", __FUNCTION__, offset->csops + addr->text_base);
        
        if(!(offset->csops2 = find_csops2_84(addr->text_base, buf, addr->text_size))) {
            FAIL(FLAG_FIND, "csops");
            goto end;
        }
        LOG("[%s] %08x: csops2", __FUNCTION__, offset->csops2 + addr->text_base);
        
        if(!(offset->pid_check = find_tfp0_patch(addr->text_base, buf, addr->text_size))) {
            FAIL(FLAG_FIND, "task_for_pid");
            goto end;
        }
        LOG("[%s] %08x: pid_check", __FUNCTION__, offset->pid_check + addr->text_base);

    } else {
        ERROR("[%s] unsupported version", __FUNCTION__);
        goto end;
    }
    
    *textOffset = offset;
    return 0;
end:
    if(offset)
        free((void *)offset);
    return -1;
}

static int find_amfi_offset(unsigned char* buf, struct macho_address *addr, struct amfi_offset **amfiOffset)
{
    struct amfi_offset *offset = (struct amfi_offset *)malloc(sizeof(struct amfi_offset));
    if(!offset) {
        ERROR("[%s] failed to allocate buffer!", __FUNCTION__);
        goto end;
    }
    
    memset(offset, '\0', sizeof(struct amfi_offset));
    
    if(majorVer == 3248) {
        // ios 9.x
        // __got
        if(!(offset->i_can_has_debugger_got = find_amfi_PE_i_can_has_debugger_got(addr->text_base, buf+addr->text_buf_base, addr->text_size + addr->data_size))) {
            FAIL(FLAG_FIND, "i_can_has_debugger_got");
            goto end;
        }
        if(!(offset->cs_enforcement_got = find_amfi_cs_enforcement_got(addr->text_base, buf+addr->text_buf_base, addr->text_size + addr->data_size))) {
            FAIL(FLAG_FIND, "cs_enforcement_got");
            goto end;
        }
        // text
        if(!(offset->execve_hook = find_amfi_execve_ret(addr->text_base, buf+addr->text_buf_base, addr->text_size))) {
            FAIL(FLAG_FIND, "execve_hook");
            goto end;
        }
        
        LOG("[%s] %08x: amfi_PE_i_can_has_debugger_got", __FUNCTION__, offset->i_can_has_debugger_got + addr->text_base);
        LOG("[%s] %08x: amfi_cs_enforcement_got", __FUNCTION__, offset->cs_enforcement_got + addr->text_base);
        LOG("[%s] %08x: execve_hook", __FUNCTION__, offset->execve_hook + addr->text_base);
    } else if(majorVer == 2784 || majorVer == 2783) {
        if(!(offset->i_can_has_debugger_got = find_amfi_PE_i_can_has_debugger_got_84(addr->text_base, buf+addr->text_buf_base, addr->text_size + addr->data_size))) {
            FAIL(FLAG_FIND, "i_can_has_debugger_got");
            goto end;
        }
        LOG("[%s] %08x: amfi_PE_i_can_has_debugger_got", __FUNCTION__, offset->i_can_has_debugger_got + addr->text_base);
        if(!(offset->cs_enforcement_got = find_amfi_cs_enforcement_got_84(addr->text_base, buf+addr->text_buf_base, addr->text_size + addr->data_size))) {
            FAIL(FLAG_FIND, "cs_enforcement_got");
            goto end;
        }
        LOG("[%s] %08x: amfi_cs_enforcement_got", __FUNCTION__, offset->cs_enforcement_got + addr->text_base);
    } else if(majorVer == 2107) {
        // ios 6.x
        if(!(offset->i_can_has_debugger_got = find_amfi_PE_i_can_has_debugger_got_ios6(addr->text_base, buf+addr->text_buf_base, addr->text_size + addr->data_size))) {
            FAIL(FLAG_FIND, "i_can_has_debugger_got");
            goto end;
        }
        
        LOG("[%s] %08x: amfi_PE_i_can_has_debugger_got", __FUNCTION__, offset->i_can_has_debugger_got + addr->text_base);
    } else {
        ERROR("[%s] unsupported version", __FUNCTION__);
        goto end;
    }
    
    *amfiOffset = offset;
    return 0;
end:
    if(offset)
        free((void *)offset);
    return -1;
}

static int find_sandbox_offset(unsigned char* buf, struct macho_address *addr, struct sandbox_offset **sbOffset)
{
    struct sandbox_offset *offset = (struct sandbox_offset *)malloc(sizeof(struct sandbox_offset));
    if(!offset) {
        ERROR("[%s] failed to allocate buffer!", __FUNCTION__);
        goto end;
    }
    
    memset(offset, '\0', sizeof(struct sandbox_offset));
    
    if(majorVer == 3248) {
        if(!(offset->i_can_has_debugger_got = find_sb_PE_i_can_has_debugger_got(addr->text_base, buf+addr->text_buf_base, addr->text_size + addr->data_size, 0))) {
            FAIL(FLAG_FIND, "i_can_has_debugger_got");
            goto end;
        }
        if(!(offset->ops = find_sandbox_mac_policy_ops(addr->text_base, buf+addr->text_buf_base, addr->text_size + addr->data_size))) {
            FAIL(FLAG_FIND, "mac_policy_ops");
            goto end;
        }
        
        LOG("[%s] %08x: sb_PE_i_can_has_debugger_got", __FUNCTION__, offset->i_can_has_debugger_got + addr->text_base);
        LOG("[%s] %08x: sandbox_mac_policy_ops", __FUNCTION__, offset->ops + addr->text_base);
        
    } else if(majorVer == 2784 || majorVer == 2783) {
        // ios 6.x
        if(!(offset->i_can_has_debugger_got = find_sb_PE_i_can_has_debugger_got_84(addr->text_base, buf+addr->text_buf_base, addr->text_size + addr->data_size))) {
            FAIL(FLAG_FIND, "i_can_has_debugger_got");
            goto end;
        }
        LOG("[%s] %08x: sb_PE_i_can_has_debugger_got", __FUNCTION__, offset->i_can_has_debugger_got + addr->text_base);
        if(!(offset->sb_evaluate = find_sb_patch(addr->text_base, buf+addr->text_buf_base, addr->text_size))) {
            FAIL(FLAG_FIND, "sb_evaluate");
            goto end;
        }
        LOG("[%s] %08x: sb_evaluate", __FUNCTION__, offset->sb_evaluate + addr->text_base);
    } else if(majorVer == 2107) {
        // ios 6.x
        if(!(offset->i_can_has_debugger_got = find_sb_PE_i_can_has_debugger_got_ios6(addr->text_base, buf+addr->text_buf_base, addr->text_size + addr->data_size, 0))) {
            FAIL(FLAG_FIND, "i_can_has_debugger_got");
            goto end;
        }
        if(!(offset->sb_evaluate = find_sb_patch(addr->text_base, buf+addr->text_buf_base, addr->text_size))) {
            FAIL(FLAG_FIND, "sb_evaluate");
            goto end;
        }
        LOG("[%s] %08x: sb_PE_i_can_has_debugger_got", __FUNCTION__, offset->i_can_has_debugger_got + addr->text_base);
        LOG("[%s] %08x: sb_evaluate", __FUNCTION__, offset->sb_evaluate + addr->text_base);
    } else {
        ERROR("[%s] unsupported version", __FUNCTION__);
        goto end;
    }
    
    *sbOffset = offset;
    return 0;
end:
    if(offset)
        free((void *)offset);
    return -1;
}

static int find_lwvm_offset(unsigned char* buf, struct macho_address *addr, struct lwvm_offset **lwvmOffset)
{
    struct lwvm_offset *offset = (struct lwvm_offset *)malloc(sizeof(struct lwvm_offset));
    if(!offset) {
        ERROR("[%s] failed to allocate buffer!", __FUNCTION__);
        goto end;
    }
    
    memset(offset, '\0', sizeof(struct lwvm_offset));
    
    if(majorVer == 3248) {
        if(minorVer > 32) {
            // ios 9.3-9.3.6
            if(!(offset->i_can_has_kernel_configuration_got = find_PE_i_can_has_kernel_configuration_got(addr->text_base, buf+addr->text_buf_base, addr->text_size + addr->data_size))) {
                FAIL(FLAG_FIND, "i_can_has_kernel_configuration_got");
                goto end;
            }
            LOG("[%s] %08x: %s", __FUNCTION__,offset->i_can_has_kernel_configuration_got + addr->text_base, (minorVer > 42) ? "lwvm_krnl_conf_got":"lwvm_i_can_has_debugger_got");
            
            if(!(offset->jump = find_lwvm_jump(addr->text_base, buf+addr->text_buf_base, addr->text_size))) {
                FAIL(FLAG_FIND, "lwvm_jump");
                goto end;
            }
            offset->jump += addr->text_base;
            LOG("[%s] %08x: lwvm_jump", __FUNCTION__, offset->jump);
            
        } else {
            // 9.0-9.2.1
            if(!(offset->mapForIO = find_mapForIO(addr->text_base, buf+addr->text_buf_base, addr->text_size))) {
                FAIL(FLAG_FIND, "mapForIO");
                goto end;
            }
            LOG("[%s] %08x: mapForIO", __FUNCTION__, offset->mapForIO + addr->text_base);
        }
       
    } else if(majorVer == 2784 || majorVer == 2783) {
        if(!(offset->mapForIO = find_mapForIO_84(addr->text_base, buf+addr->text_buf_base, addr->text_size))) {
            FAIL(FLAG_FIND, "mapForIO");
            goto end;
        }
        LOG("[%s] %08x: mapForIO", __FUNCTION__, offset->mapForIO + addr->text_base);
    } else if(majorVer == 2107) {
        LOG("[%s] SKIP", __FUNCTION__);
        goto ret0;
    } else {
        ERROR("[%s] unsupported version", __FUNCTION__);
        goto end;
    }

ret0:
    *lwvmOffset = offset;
    return 0;
end:
    if(offset)
        free((void *)offset);
    return -1;
}

// patch
static int write_amfi_execve_hook_payload(void* buf, size_t bufsize, uint32_t addr)
{
    if(addr+30 > bufsize) {
        ERROR("[%s] overflow!", __FUNCTION__);
        return -1;
    }
    
    int i = 0;
    *(uint32_t*)(buf + addr+i) = 0x0000F8DA; i+=4; // ldr.w   r0, [sl]            @ cs_flags
    *(uint32_t*)(buf + addr+i) = 0x6080F040; i+=4; // orr     r0, r0, #0x4000000  @ CS_PLATFORM_BINARY
    *(uint32_t*)(buf + addr+i) = 0x000FF040; i+=4; // orr     r0, r0, #0x000f     @ CS_VALID | CS_ADHOC | CS_GET_TASK_ALLOW | CS_INSTALLER
    *(uint32_t*)(buf + addr+i) = 0x507CF420; i+=4; // bic     r0, r0, #0x3f00     @ clearing CS_HARD | CS_KILL | CS_CHECK_EXPIRATION | CS_RESTRICT | CS_ENFORCEMENT | CS_REQUIRE_LV
    *(uint32_t*)(buf + addr+i) = 0x0000F8CA; i+=4; // str.w   r0, [sl]
    *(uint16_t*)(buf + addr+i) = 0x2000; i+=2;     // movs    r0, #0x0
    *(uint16_t*)(buf + addr+i) = 0xB006; i+=2;     // add     sp, #0x18
    *(uint32_t*)(buf + addr+i) = 0x0D00E8BD; i+=4; // pop.w   {r8, sl, fp}
    *(uint16_t*)(buf + addr+i) = 0xBDF0; i+=2;     // pop     {r4, r5, r6, r7, pc}
    
    return 0;
}

void ops(void* buf, uint32_t addr, uint32_t ret0_gadget)
{
    if(*(uint32_t*)(buf + addr) != 0)
        *(uint32_t*)(buf + addr) = ret0_gadget;
    else
        LOG("[%s] SKIP", __FUNCTION__);
    return;
}

static int patch_sbops(void* buf, size_t bufsize, uint32_t addr, uint32_t ret0_gadget)
{
    if(addr+sizeof(struct mac_policy_ops) > bufsize) {
        ERROR("[%s] overflow!", __FUNCTION__);
        return -1;
    }
    
    LOG("[%s] MAC policies", __FUNCTION__);
    if(majorVer == 3248) {
        // ios 9.x
        if(minorVer > 11) {
            ops(buf,  addr + offsetof(struct mac_policy_ops, mpo_proc_check_fork), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops, mpo_iokit_check_open), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops, mpo_mount_check_fsctl), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops, mpo_vnode_check_rename), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops, mpo_vnode_check_access), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops, mpo_vnode_check_chroot), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops, mpo_vnode_check_create), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops, mpo_vnode_check_deleteextattr), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops, mpo_vnode_check_exchangedata), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops, mpo_vnode_check_getattrlist), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops, mpo_vnode_check_getextattr), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops, mpo_vnode_check_ioctl), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops, mpo_vnode_check_link), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops, mpo_vnode_check_listextattr), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops, mpo_vnode_check_open), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops, mpo_vnode_check_readlink), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops, mpo_vnode_check_revoke), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops, mpo_vnode_check_setattrlist), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops, mpo_vnode_check_setextattr), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops, mpo_vnode_check_setflags), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops, mpo_vnode_check_setmode), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops, mpo_vnode_check_setowner), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops, mpo_vnode_check_stat), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops, mpo_vnode_check_truncate), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops, mpo_vnode_check_unlink), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops, mpo_file_check_mmap), ret0_gadget);
        } else {
            ops(buf,  addr + offsetof(struct mac_policy_ops90, mpo_proc_check_fork), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops90, mpo_iokit_check_open), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops90, mpo_mount_check_fsctl), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops90, mpo_vnode_check_rename), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops90, mpo_vnode_check_access), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops90, mpo_vnode_check_chroot), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops90, mpo_vnode_check_create), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops90, mpo_vnode_check_deleteextattr), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops90, mpo_vnode_check_exchangedata), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops90, mpo_vnode_check_getattrlist), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops90, mpo_vnode_check_getextattr), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops90, mpo_vnode_check_ioctl), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops90, mpo_vnode_check_link), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops90, mpo_vnode_check_listextattr), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops90, mpo_vnode_check_open), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops90, mpo_vnode_check_readlink), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops90, mpo_vnode_check_revoke), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops90, mpo_vnode_check_setattrlist), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops90, mpo_vnode_check_setextattr), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops90, mpo_vnode_check_setflags), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops90, mpo_vnode_check_setmode), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops90, mpo_vnode_check_setowner), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops90, mpo_vnode_check_setutimes), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops90, mpo_vnode_check_stat), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops90, mpo_vnode_check_truncate), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops90, mpo_vnode_check_unlink), ret0_gadget);
            ops(buf,  addr + offsetof(struct mac_policy_ops90, mpo_file_check_mmap), ret0_gadget);
        }
    } else {
        ERROR("[%s] unsupported version", __FUNCTION__);
        return -1;
    }
    
    return 0;
}

static int patch_text(unsigned char* buf, struct macho_address *addr, struct text_offset *offset)
{
    if(majorVer == 3248) {
        // ios 9.x
        if(write32(buf, addr->text_size, offset->pid_check, 0xBF00BF00)) {
            FAIL(FLAG_PATCH, "pid_check");
            goto end;
        }
        LOG("[%s] patched: pid_check", __FUNCTION__);
        
        if(write16(buf, addr->text_size, offset->vm_fault_enter, 0x2201)) {
            FAIL(FLAG_PATCH, "vm_fault_enter");
            goto end;
        }
        LOG("[%s] patched: vm_fault_enter", __FUNCTION__);
        
        if(write32(buf, addr->text_size, offset->vm_map_enter, 0xBF00BF00)) {
            FAIL(FLAG_PATCH, "vm_map_enter");
            goto end;
        }
        LOG("[%s] patched: vm_map_enter", __FUNCTION__);
        
        if(write32(buf, addr->text_size, offset->vm_map_protect, 0xBF00BF00)) {
            FAIL(FLAG_PATCH, "vm_map_protect");
            goto end;
        }
        LOG("[%s] patched: vm_map_protect", __FUNCTION__);
        
        if(write32(buf, addr->text_size, offset->csops, 0xBF00BF00)) {
            FAIL(FLAG_PATCH, "csops");
            goto end;
        }
        LOG("[%s] patched: csops", __FUNCTION__);
        
        if(minorVer == 1) {
            if(write8(buf, addr->text_size, offset->mac_mount, 0xE7)) {
                FAIL(FLAG_PATCH, "mac_mount");
                goto end;
            }
        } else {
            if(write8(buf, addr->text_size, offset->mac_mount, 0xE0)) {
                FAIL(FLAG_PATCH, "mac_mount");
                goto end;
            }
        }
        LOG("[%s] patched: mac_mount", __FUNCTION__);
       
    } else if(majorVer == 2784 || majorVer == 2783) {
        if(write32(buf, addr->text_size, offset->pid_check, 0xBF00BF00)) {
            FAIL(FLAG_PATCH, "pid_check");
            goto end;
        }
        LOG("[%s] patched: pid_check", __FUNCTION__);
        
        if(write32(buf, addr->text_size, offset->vm_fault_enter, 0x2201bf00)) {
            FAIL(FLAG_PATCH, "vm_fault_enter");
            goto end;
        }
        LOG("[%s] patched: vm_fault_enter", __FUNCTION__);
        
        if(write32(buf, addr->text_size, offset->vm_map_enter, 0x4280bf00)) {
            FAIL(FLAG_PATCH, "vm_map_enter");
            goto end;
        }
        LOG("[%s] patched: vm_map_enter", __FUNCTION__);
        
        if(write32(buf, addr->text_size, offset->vm_map_protect, 0xbf00bf00)) {
            FAIL(FLAG_PATCH, "vm_map_protect");
            goto end;
        }
        LOG("[%s] patched: vm_map_protect", __FUNCTION__);
        
        if(write32(buf, addr->text_size, offset->csops, 0xBF00BF00)) {
            FAIL(FLAG_PATCH, "csops");
            goto end;
        }
        LOG("[%s] patched: csops", __FUNCTION__);
        
        if(write8(buf, addr->text_size, offset->csops2, 0x20)) {
            FAIL(FLAG_PATCH, "csops2");
            goto end;
        }
        LOG("[%s] patched: csops2", __FUNCTION__);
        
        if(write8(buf, addr->text_size, offset->mac_mount, 0xE0)) {
            FAIL(FLAG_PATCH, "mac_mount");
            goto end;
        }
        LOG("[%s] patched: mac_mount", __FUNCTION__);
        
    } else if(majorVer == 2107) {
        // ios 6.x
        if(write16(buf, addr->text_size, offset->vm_map_enter, 0xBF00)) {
            FAIL(FLAG_PATCH, "vm_map_enter");
            goto end;
        }
        LOG("[%s] patched: vm_map_enter", __FUNCTION__);
        
        if(write16(buf, addr->text_size, offset->vm_map_protect, 0xE005)) {
            FAIL(FLAG_PATCH, "vm_map_protect");
            goto end;
        }
        LOG("[%s] patched: vm_map_protect", __FUNCTION__);
        
        if(write16(buf, addr->text_size, offset->pid_check, 0xE006)) {
            FAIL(FLAG_PATCH, "pid_check");
            goto end;
        }
        LOG("[%s] patched: pid_check", __FUNCTION__);
    } else {
        ERROR("[%s] unsupported version", __FUNCTION__);
        goto end;
    }
    
    return 0;
    
end:
    return -1;
}

static int patch_amfi(unsigned char* buf, struct macho_address *kext, struct macho_address *kaddr,
                      struct amfi_offset *offset, struct helper_offset *helper)
{
    size_t maxrange = kext->text_size + kext->data_size;
    
    if(majorVer == 3248) {
        if(write32(buf + kext->text_buf_base, maxrange, offset->i_can_has_debugger_got, helper->ret1_gadget)) {
            FAIL(FLAG_PATCH, "i_can_has_debugger_got");
            goto end;
        }
        LOG("[%s] patched: amfi_PE_i_can_has_debugger_got", __FUNCTION__);
        
        if(write32(buf + kext->text_buf_base, maxrange, offset->cs_enforcement_got, helper->ret0_gadget)) {
            FAIL(FLAG_PATCH, "cs_enforcement_got");
            goto end;
        }
        LOG("[%s] patched: amfi_cs_enforcement_got", __FUNCTION__);
        
        uint32_t unbase_addr = offset->execve_hook + kext->text_base - kaddr->text_base;
        uint32_t unbase_shc = kaddr->last_section - kaddr->text_base;
        uint32_t val = make_b_w(unbase_addr, unbase_shc);
        if(!unbase_addr || !unbase_shc) {
            FAIL(FLAG_GET, "unbase offset");
            goto end;
        }
        if(!val) {
            FAIL(FLAG_GET, "b insn");
            goto end;
        }
        DEBUGLOG("[%s] bl: %08x, %08x, %08x", __FUNCTION__, unbase_addr, unbase_shc, val);
        
        if(write32(buf + kext->text_buf_base, kext->text_size, offset->execve_hook, val)) {
            FAIL(FLAG_PATCH, "execve_hook");
            goto end;
        }
        LOG("[%s] patched: execve_hook", __FUNCTION__);
        
        if(write_amfi_execve_hook_payload(buf, kaddr->text_size, kaddr->last_section - (kaddr->text_base - kaddr->text_buf_base))) {
            FAIL(FLAG_PATCH, "execve_hook_payload");
            goto end;
        }
        LOG("[%s] patched: amfi_execve_hook_payload", __FUNCTION__);
    
    } else if(majorVer == 2784 || majorVer == 2783) {
        if(write32(buf + kext->text_buf_base, maxrange, offset->i_can_has_debugger_got, helper->ret1_gadget)) {
            FAIL(FLAG_PATCH, "i_can_has_debugger_got");
            goto end;
        }
        LOG("[%s] patched: amfi_PE_i_can_has_debugger_got", __FUNCTION__);
        
        if(write32(buf + kext->text_buf_base, maxrange, offset->cs_enforcement_got, helper->ret0_gadget)) {
            FAIL(FLAG_PATCH, "cs_enforcement_got");
            goto end;
        }
        LOG("[%s] patched: amfi_cs_enforcement_got", __FUNCTION__);
    } else if(majorVer == 2107) {
        if(write32(buf + kext->text_buf_base, maxrange, offset->i_can_has_debugger_got, helper->ret1_gadget)) {
            FAIL(FLAG_PATCH, "i_can_has_debugger_got");
            goto end;
        }
        LOG("[%s] patched: amfi_PE_i_can_has_debugger_got", __FUNCTION__);
    } else {
        ERROR("[%s] unsupported version", __FUNCTION__);
        goto end;
    }
    
    return 0;
    
end:
    return -1;
}

// evasi0n6
static int hook_sb_evaluate6(unsigned char* buf, struct macho_address *kext, struct macho_address *kaddr,
                            struct sandbox_offset *offset, struct helper_offset *helper)
{
    uint32_t backup = *(uint32_t*)((buf + kext->text_buf_base) + offset->sb_evaluate);
    if(!backup) {
        FAIL(FLAG_GET, "backup opcode");
        goto end;
    }
    
    LOG("[%s] backup: %08x", __FUNCTION__, backup);
    
    // check opcode
    uint16_t* insn = (uint16_t*)((buf + kext->text_buf_base) + offset->sb_evaluate);
    if(insn_is_32bit(insn)) {
        // 32-bit: pass
        DEBUGLOG("[%s] detected: 32-bit insn ... pass", __FUNCTION__);
    } else {
        // 16-bit: check
        DEBUGLOG("[%s] detected: 16-bit insn", __FUNCTION__);
        
        insn += 1; // push 1-insn
        DEBUGLOG("[%s] push: 1-insn", __FUNCTION__);
        
        // check
        if(insn_is_32bit(insn)) {
            ERROR("[%s] detected: 32-bit insn ... overflow", __FUNCTION__);
            goto end; // 32-bit: overflow
        }
        DEBUGLOG("[%s] detected: 16-bit insn ... ok", __FUNCTION__);
    }
    insn = NULL;
    
    uint32_t unbaseLast = kaddr->last_section - kaddr->text_base;
    if(!unbaseLast) {
        FAIL(FLAG_GET, "unbase last");
        goto end;
    }
    LOG("[%s] unbaseLast: %08x", __FUNCTION__, unbaseLast);
    
    uint32_t unbaseOrig = (offset->sb_evaluate + kext->text_base) - kaddr->text_base;
    if(!unbaseOrig) {
        FAIL(FLAG_GET, "unbase orig");
        goto end;
    }
    LOG("[%s] unbaseOrig: %08x", __FUNCTION__, unbaseOrig);
    
    uint32_t opcode        = make_b_w(unbaseOrig, unbaseLast);
    uint32_t vn_getpath_bl = make_bl(unbaseLast + VN_GETPATH_BL_OFFSET6, helper->vn_getpath);
    uint32_t memcmp_bl_1   = make_bl(unbaseLast + MEMCMP_BL_1_OFFSET6,   helper->memcmp);
    uint32_t memcmp_bl_2   = make_bl(unbaseLast + MEMCMP_BL_2_OFFSET6,   helper->memcmp);
    uint32_t memcmp_bl_3   = make_bl(unbaseLast + MEMCMP_BL_3_OFFSET6,   helper->memcmp);
    uint32_t jumpback      = make_b_w(unbaseLast + JUMPBACK_OFFSET6, unbaseOrig + 4);
    
    if(!(opcode && vn_getpath_bl && jumpback &&
         memcmp_bl_1 && memcmp_bl_2 && memcmp_bl_3)) {
        FAIL(FLAG_GET, "bl insn");
        goto end;
    }
    
    LOG("[%s] opcode: %08x", __FUNCTION__, opcode);
    LOG("[%s] vn_getpath: %08x", __FUNCTION__, vn_getpath_bl);
    LOG("[%s] memcmp: %08x - %08x - %08x", __FUNCTION__, memcmp_bl_1, memcmp_bl_2, memcmp_bl_3);
    LOG("[%s] jumpback: %08x", __FUNCTION__, jumpback);
    
    if(sbPayloadLen6 > 0x100) {
        ERROR("[%s] payload size is too large", __FUNCTION__);
        goto end;
    }
    
    unsigned char* sbBuf = malloc(sbPayloadLen6);
    if(!sbBuf) {
        ERROR("[%s] failed to allocate buffer!", __FUNCTION__);
        goto end;
    }
    
    memset(sbBuf, '\0', sbPayloadLen6);
    memcpy(sbBuf, sbPayload6, sbPayloadLen6);
    
    *(uint32_t*)(sbBuf + VN_GETPATH_BL_OFFSET6) = vn_getpath_bl;
    *(uint32_t*)(sbBuf + MEMCMP_BL_1_OFFSET6)   = memcmp_bl_1;
    *(uint32_t*)(sbBuf + MEMCMP_BL_2_OFFSET6)   = memcmp_bl_2;
    *(uint32_t*)(sbBuf + MEMCMP_BL_3_OFFSET6)   = memcmp_bl_3;
    *(uint32_t*)(sbBuf + RESTORE_OFFSET6)       = backup;
    *(uint32_t*)(sbBuf + JUMPBACK_OFFSET6)      = jumpback;
    
    LOG("[%s] writing payload", __FUNCTION__);
    if(write32(buf + kext->text_buf_base, kext->text_size, offset->sb_evaluate, opcode)) {
        FAIL(FLAG_PATCH, "sb_evaluate");
        goto end;
    }
    memcpy((buf + unbaseLast), sbBuf, sbPayloadLen6);
    
    free(sbBuf);
    sbBuf = NULL;
    
    return 0;
    
end:
    return -1;
}

// taig
__unused static int hook_sb_evaluate(unsigned char* buf, struct macho_address *kext, struct macho_address *kaddr,
                            struct sandbox_offset *offset, struct helper_offset *helper)
{
    uint32_t backup = *(uint32_t*)((buf + kext->text_buf_base) + offset->sb_evaluate);
    if(!backup) {
        FAIL(FLAG_GET, "backup opcode");
        goto end;
    }
    
    LOG("[%s] backup: %08x", __FUNCTION__, backup);
    
    // check opcode
    uint16_t* insn = (uint16_t*)((buf + kext->text_buf_base) + offset->sb_evaluate);
    if(insn_is_32bit(insn)) {
        // 32-bit: pass
        DEBUGLOG("[%s] detected: 32-bit insn ... pass", __FUNCTION__);
    } else {
        // 16-bit: check
        DEBUGLOG("[%s] detected: 16-bit insn", __FUNCTION__);
        
        insn += 1; // push 1-insn
        DEBUGLOG("[%s] push: 1-insn", __FUNCTION__);
        
        // check
        if(insn_is_32bit(insn)) {
            ERROR("[%s] detected: 32-bit insn ... overflow", __FUNCTION__);
            goto end; // 32-bit: overflow
        }
        DEBUGLOG("[%s] detected: 16-bit insn ... ok", __FUNCTION__);
    }
    insn = NULL;
    
    uint32_t unbaseLast = kaddr->last_section - kaddr->text_base;
    if(!unbaseLast) {
        FAIL(FLAG_GET, "unbase last");
        goto end;
    }
    LOG("[%s] unbaseLast: %08x", __FUNCTION__, unbaseLast);
    
    uint32_t unbaseOrig = (offset->sb_evaluate + kext->text_base) - kaddr->text_base;
    if(!unbaseOrig) {
        FAIL(FLAG_GET, "unbase orig");
        goto end;
    }
    LOG("[%s] unbaseOrig: %08x", __FUNCTION__, unbaseOrig);
    
    uint32_t opcode        = make_b_w(unbaseOrig, unbaseLast);
    uint32_t vn_getpath_bl = make_bl(unbaseLast + VN_GETPATH_BL_OFFSET, helper->vn_getpath);
    uint32_t memcmp_bl_1   = make_bl(unbaseLast + MEMCMP_BL_1_OFFSET,   helper->memcmp);
    uint32_t memcmp_bl_2   = make_bl(unbaseLast + MEMCMP_BL_2_OFFSET,   helper->memcmp);
    uint32_t memcmp_bl_3   = make_bl(unbaseLast + MEMCMP_BL_3_OFFSET,   helper->memcmp);
    uint32_t memcmp_bl_4   = make_bl(unbaseLast + MEMCMP_BL_4_OFFSET,   helper->memcmp);
    uint32_t jumpback      = make_b_w(unbaseLast + JUMPBACK_OFFSET, unbaseOrig + 4);
    
    if(!(opcode && vn_getpath_bl && jumpback &&
         memcmp_bl_1 && memcmp_bl_2 && memcmp_bl_3 && memcmp_bl_4)) {
        FAIL(FLAG_GET, "bl insn");
        goto end;
    }
    
    LOG("[%s] opcode: %08x", __FUNCTION__, opcode);
    LOG("[%s] vn_getpath: %08x", __FUNCTION__, vn_getpath_bl);
    LOG("[%s] memcmp: %08x - %08x - %08x - %08x", __FUNCTION__, memcmp_bl_1, memcmp_bl_2, memcmp_bl_3, memcmp_bl_4);
    LOG("[%s] jumpback: %08x", __FUNCTION__, jumpback);
    
    if(sbPayloadLen > 0x100) {
        ERROR("[%s] payload size is too large", __FUNCTION__);
        goto end;
    }
    
    unsigned char* sbBuf = malloc(sbPayloadLen);
    
    if(!sbBuf) {
        ERROR("[%s] failed to allocate buffer!", __FUNCTION__);
        goto end;
    }
    
    memset(sbBuf, '\0', sbPayloadLen);
    memcpy(sbBuf, sbPayload, sbPayloadLen);
    
    *(uint32_t*)(sbBuf + VN_GETPATH_BL_OFFSET) = vn_getpath_bl;
    *(uint32_t*)(sbBuf + MEMCMP_BL_1_OFFSET)   = memcmp_bl_1;
    *(uint32_t*)(sbBuf + MEMCMP_BL_2_OFFSET)   = memcmp_bl_2;
    *(uint32_t*)(sbBuf + MEMCMP_BL_3_OFFSET)   = memcmp_bl_3;
    *(uint32_t*)(sbBuf + MEMCMP_BL_4_OFFSET)   = memcmp_bl_4;
    *(uint32_t*)(sbBuf + RESTORE_OFFSET)       = backup;
    *(uint32_t*)(sbBuf + JUMPBACK_OFFSET)      = jumpback;
    
    LOG("[%s] writing payload", __FUNCTION__);
    if(write32(buf + kext->text_buf_base, kext->text_size, offset->sb_evaluate, opcode)) {
        FAIL(FLAG_PATCH, "sb_evaluate");
        goto end;
    }
    memcpy((buf + unbaseLast), sbBuf, sbPayloadLen);
    
    free(sbBuf);
    sbBuf = NULL;
    
    return 0;
    
end:
    return -1;
}

static int patch_sandbox(unsigned char* buf, struct macho_address *kext, struct macho_address *kaddr,
                      struct sandbox_offset *offset, struct helper_offset *helper)
{
    size_t maxrange = kext->text_size + kext->data_size;
    if(majorVer == 3248) {
        if(write32(buf + kext->text_buf_base, maxrange, offset->i_can_has_debugger_got, helper->ret1_gadget)) {
            FAIL(FLAG_PATCH, "i_can_has_debugger_got");
            goto end;
        }
        LOG("[%s] patched: sb_PE_i_can_has_debugger_got", __FUNCTION__);
        if(patch_sbops(buf + kext->text_buf_base, maxrange, offset->ops, helper->ret0_gadget)) {
            FAIL(FLAG_PATCH, "mac_policy_ops");
            goto end;
        }
        LOG("[%s] patched: sandbox_mac_policy_ops", __FUNCTION__);
        
    } else if(majorVer == 2784 || majorVer == 2783) {
        if(write32(buf + kext->text_buf_base, maxrange, offset->i_can_has_debugger_got, helper->ret1_gadget)) {
            FAIL(FLAG_PATCH, "i_can_has_debugger_got");
            goto end;
        }
        LOG("[%s] patched: sb_PE_i_can_has_debugger_got", __FUNCTION__);
        
        if(hook_sb_evaluate(buf, kext, kaddr, offset, helper)) {
            FAIL(FLAG_PATCH, "hook_sb_evaluate");
            goto end;
        }
        LOG("[%s] hooked: sb_evaluate", __FUNCTION__);
    } else if(majorVer == 2107) {
        if(write32(buf + kext->text_buf_base, maxrange, offset->i_can_has_debugger_got, helper->ret1_gadget)) {
            FAIL(FLAG_PATCH, "i_can_has_debugger_got");
            goto end;
        }
        LOG("[%s] patched: sb_PE_i_can_has_debugger_got", __FUNCTION__);
        
        
        if(hook_sb_evaluate6(buf, kext, kaddr, offset, helper)) {
            FAIL(FLAG_PATCH, "hook_sb_evaluate");
            goto end;
        }
        LOG("[%s] hooked: sb_evaluate", __FUNCTION__);
    } else {
        ERROR("[%s] unsupported version", __FUNCTION__);
        goto end;
    }
    
    return 0;
    
end:
    return -1;
}

static int patch_lwvm(unsigned char* buf, struct macho_address *kext, struct macho_address *kaddr,
                         struct lwvm_offset *offset, struct helper_offset *helper)
{
    size_t maxrange = kext->text_size + kext->data_size;
    
    if(majorVer == 3248) {
        if(minorVer > 32) {
            if(write32(buf + kext->text_buf_base, maxrange, offset->i_can_has_kernel_configuration_got, offset->jump)) {
                FAIL(FLAG_PATCH, "%s", (minorVer > 42) ? "lwvm_krnl_conf_got":"lwvm_i_can_has_debugger_got");
                goto end;
            }
            LOG("[%s] patched: %s", __FUNCTION__, (minorVer > 42) ? "lwvm_krnl_conf_got":"lwvm_i_can_has_debugger_got");
        } else {
            if(write32(buf + kext->text_buf_base, kext->text_size, offset->mapForIO, 0xbf00bf00)) {
                FAIL(FLAG_PATCH, "mapForIO");
                goto end;
            }
            LOG("[%s] patched: mapForIO", __FUNCTION__);
        }
        
    } else if(majorVer == 2784 || majorVer == 2783) {
        if(write32(buf + kext->text_buf_base, kext->text_size, offset->mapForIO, 0xbf00bf00)) {
            FAIL(FLAG_PATCH, "mapForIO");
            goto end;
        }
        LOG("[%s] patched: mapForIO", __FUNCTION__);
    } else if(majorVer == 2107) {
        LOG("[%s] SKIP", __FUNCTION__);
        goto ret0;
    } else {
        goto end;
    }

ret0:
    return 0;
end:
    return -1;
}


int patchKernel(AbstractFile* inFile, AbstractFile* outFile)
{
    
    bool supported = false;
    __unused int i = 0;
    __unused int flags = PATCH_NONE;
    unsigned char* buf = NULL;
    size_t sz = 0;
    
    sz = (size_t) inFile->getLength(inFile);
    buf = (unsigned char*) malloc(sz);
    if(!buf) {
        ERROR("[%s] failed to allocate buffer!", __FUNCTION__);
        goto end;
    }
    inFile->read(inFile, buf, sz);
    
    DEBUGLOG("[%s] filesize: %zx", __FUNCTION__, sz);
    
    // search
    struct macho_address *kaddr = NULL;
    struct macho_address *amfiaddr = NULL;
    struct macho_address *sbaddr = NULL;
    struct macho_address *lwvmaddr = NULL;
    
    struct helper_offset *helperOffset = NULL;
    struct text_offset *textOffset = NULL;
    struct amfi_offset *amfiOffset = NULL;
    struct sandbox_offset *sbOffset = NULL;
    struct lwvm_offset *lwvmOffset = NULL;
    
    if(init_kernel(buf, &kaddr)) {
        ERROR("[%s] failed to init kernel", __FUNCTION__);
        goto end;
    }
    
    // check xnu version
    if (majorVer == 2107) {
        if(minorVer == 2) {
            // 6.0.x
            DEBUGLOG("[%s] Detected: %s", __FUNCTION__, "6.0");
            supported = true;
        } else if(minorVer == 7) {
            // 6.1.x
            DEBUGLOG("[%s] Detected: %s", __FUNCTION__, "6.1");
            supported = true;
        }
    } else if (majorVer == 2783) {
        // 8.3-8.4.1
        DEBUGLOG("[%s] Detected: %s", __FUNCTION__, "8.0-8.2");
        supported = true;
    } else if (majorVer == 2784) {
        // 8.3-8.4.1
        DEBUGLOG("[%s] Detected: %s", __FUNCTION__, "8.3-8.4.1");
        supported = true;
    } else if (majorVer == 3248) {
        if(minorVer < 32) {
            // 9.0-9.2.1
            DEBUGLOG("[%s] Detected: %s", __FUNCTION__, "9.0-9.2.1");
            supported = true;
        } else if(minorVer < 42) {
            // 9.3-9.3.1
            DEBUGLOG("[%s] Detected: %s", __FUNCTION__, "9.3-9.3.1");
            supported = true;
        } else {
            // 9.3.2-
            DEBUGLOG("[%s] Detected: %s", __FUNCTION__, "9.3.2+");
            supported = true;
        }
    }
    
    if(!supported) {
        ERROR("[%s] unsupported version", __FUNCTION__);
        goto end;
    }
    
    if(init_kext(buf, sz, "com.apple.driver.AppleMobileFileIntegrity", &amfiaddr)) {
        FAIL(FLAG_SET, "AMFI KEXT offsets");
        goto end;
    }
    
    if(init_kext(buf, sz, "com.apple.security.sandbox", &sbaddr)) {
        FAIL(FLAG_SET, "Sandbox KEXT offsets");
        goto end;
    }
    
    if(init_kext(buf, sz, "com.apple.driver.LightweightVolumeManager", &lwvmaddr)) {
        FAIL(FLAG_SET, "LwVM KEXT offsets");
        goto end;
    }
    
    LOG("[%s] %08x, %08x kernel_text_base",
        __FUNCTION__,
        text_base,
        kaddr->text_buf_base);
    
    LOG("[%s] %08zx, %08zx (%08lx): kernel_size",
        __FUNCTION__,
        kernel_size,
        sz,
        kernel_size-sz);
    
    LOG("[%s] %08x, %08x (%08x): AMFI_base",
        __FUNCTION__,
        amfiaddr->text_base,
        amfiaddr->text_buf_base,
        amfiaddr->delta);
    
    LOG("[%s] %08x, %08x (%08x): Sandbox_base",
        __FUNCTION__,
        sbaddr->text_base,
        sbaddr->text_buf_base,
        sbaddr->delta);
    
    LOG("[%s] %08x, %08x (%08x): LwVM_base",
        __FUNCTION__,
        lwvmaddr->text_base,
        lwvmaddr->text_buf_base,
        lwvmaddr->delta);
    
    // find
    if(find_helper_offset(buf, kaddr, &helperOffset)) {
        FAIL(FLAG_SET, "helper offsets");
        goto end;
    }
    
    if(find_text_offset(buf, kaddr, &textOffset)) {
        FAIL(FLAG_SET, "text offsets");
        goto end;
    }
    
    if(find_amfi_offset(buf, amfiaddr, &amfiOffset)) {
        FAIL(FLAG_SET, "AMFI offsets");
        goto end;
    }
    
    if(find_sandbox_offset(buf, sbaddr, &sbOffset)) {
        FAIL(FLAG_SET, "Sandbox offsets");
        goto end;
    }
    
    if(find_lwvm_offset(buf, lwvmaddr, &lwvmOffset)) {
        FAIL(FLAG_SET, "LwVM offsets");
        goto end;
    }
    
    // patch
    if(patch_text(buf, kaddr, textOffset)) {
        FAIL(FLAG_PATCH, "TEXT");
        goto end;
    }
    
    if(patch_amfi(buf, amfiaddr, kaddr, amfiOffset, helperOffset)) {
        FAIL(FLAG_PATCH, "AMFI");
        goto end;
    }
    
    if(patch_sandbox(buf, sbaddr, kaddr, sbOffset, helperOffset)) {
        FAIL(FLAG_PATCH, "Sandbox");
        goto end;
    }
    
    if(patch_lwvm(buf, lwvmaddr, kaddr, lwvmOffset, helperOffset)) {
        FAIL(FLAG_PATCH, "LwVM");
        goto end;
    }
    
    // write
    LOG("[%s] writing buf", __FUNCTION__);
    outFile->write(outFile, buf, sz);
    outFile->close(outFile);
    inFile->close(inFile);
    
    free(buf);
    return 0;
    
end:
    if(buf)
        free(buf);
    return -1;
}

int doKernelPatch(StringValue* fileValue, const char* bundlePath, OutputState** state, unsigned int* key, unsigned int* iv, int useMemory)
{
    size_t bufferSize;
    void* buffer;
    
    AbstractFile* file;
    AbstractFile* out;
    AbstractFile* outRaw;
    
    char* tmpFileName;
    
    if(useMemory) {
        bufferSize = 0;
        buffer = malloc(1);
        outRaw = createAbstractFileFromMemoryFile((void**)&buffer, &bufferSize);
    } else {
        tmpFileName = createTempFile();
        outRaw = createAbstractFileFromFile(fopen(tmpFileName, "wb"));
    }
    
    {
        if(key != NULL) {
            XLOG(0, "encrypted input... ");
            out = duplicateAbstractFile2(getFileFromOutputState(state, fileValue->value), outRaw, key, iv, NULL);
        } else {
            out = duplicateAbstractFile(getFileFromOutputState(state, fileValue->value), outRaw);
        }
        
        if(key != NULL) {
            XLOG(0, "encrypted output... ");
            file = openAbstractFile2(getFileFromOutputState(state, fileValue->value), key, iv);
        } else {
            file = openAbstractFile(getFileFromOutputState(state, fileValue->value));
        }
    }
    
    if(!file || !out) {
        XLOG(0, "file error\n");
        exit(0);
    }
    
    if(patchKernel(file, out) != 0) {
        XLOG(0, "patch failed\n");
        exit(0);
    }
    
    XLOG(0, "writing... "); fflush(stdout);
    
    if(useMemory) {
        addToOutput(state, fileValue->value, buffer, bufferSize);
    } else {
        outRaw = createAbstractFileFromFile(fopen(tmpFileName, "rb"));
        size_t length = outRaw->getLength(outRaw);
        outRaw->close(outRaw);
        addToOutput2(state, fileValue->value, NULL, length, tmpFileName);
    }
    
    XLOG(0, "success\n"); fflush(stdout);
    
    return 0;
}
