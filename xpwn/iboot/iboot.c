#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include <mach-o/loader.h>

#include <abstractfile.h>
#include <patchfinder.h>

#include <xpwn/libxpwn.h>
#include <xpwn/outputstate.h>
#include <xpwn/pwnutil.h>
#include <xpwn/nor_files.h>

#include <iboot/iboot.h>

static bool debug_enabled = true;
#define ERROR(x, ...)             do { printf("\x1b[31m[ERROR] "x"\x1b[39m\n", ##__VA_ARGS__); } while(0)
#define DEBUGLOG(x, ...)          do { if(debug_enabled) printf("\x1b[34m"x"\x1b[39m\n", ##__VA_ARGS__); } while(0)
#define LOG(x, ...)               do { printf("\x1b[32m"x"\x1b[39m\n", ##__VA_ARGS__); } while(0)

__unused static uint32_t swap32(uint32_t val)
{
    return ((val&~0xffffff00)<<24) | (((val>>8)&~0xffff00)<<16) | (((val>>16)&~0xff00)<<8) | (val>>24);
}

__unused static uint32_t OFFSET(uint32_t base, uint32_t off)
{
    if(!off) {
        //DEBUGLOG("Failed to get koffset");
        return 0;
    }
    //DEBUGLOG("%08x", base+off);
    return base+off;
}

static int write16(void* buf, size_t bufsize, uint32_t addr, uint16_t val)
{
    if(addr+2 > bufsize)
        return -1; // overflow
    *(uint16_t*)(buf + addr) = val;
    return 0;
}

static int write32(void* buf, size_t bufsize, uint32_t addr, uint32_t val)
{
    if(addr+4 > bufsize)
        return -1; // overflow
    *(uint32_t*)(buf + addr) = val;
    return 0;
}

int patchiBoot(AbstractFile* inFile, AbstractFile* outFile, const char* customBootArgs, uint32_t debugFlags)
{
    int flags = PATCH_NONE;
    
    unsigned char* buf = NULL;
    size_t sz = 0;
    __unused uint32_t text_base = 0;
    
    sz = (size_t) inFile->getLength(inFile);
    buf = (unsigned char*) malloc(sz);
    inFile->read(inFile, buf, sz);
    
    DEBUGLOG("[%s] filesize: %zx", __FUNCTION__, sz);
    
    if(*(uint32_t*)buf != 0xEA00000E) {
        ERROR("[%s] invalid image", __FUNCTION__);
        goto end;
    }
    
    int version = find_iboot_version(buf, sz);
    LOG("[%s] version: %d", __FUNCTION__, version);
    
    const char* iboot_type = find_iboot_type(buf, sz);
    LOG("[%s] iboot_type: %s", __FUNCTION__, iboot_type);
    
    if(!strcmp(iboot_type, "LLB") || !strcmp(iboot_type, "iBSS")) {
        flags |= PATCH_RSA;
    } else if(!strcmp(iboot_type, "iBoot")) {
        flags |= PATCH_RSA|debugFlags|PATCH_BOOT_PARTITION|PATCH_BOOT_RAMDISK|PATCH_BOOTARGS;
        if(version > 2261)
            flags |= PATCH_CALL_SETENV;
    } else if(!strcmp(iboot_type, "iBEC")) {
        flags |= PATCH_RSA|PATCH_DEBUG|PATCH_TICKET|PATCH_BOOTARGS|PATCH_RAMDISK_BOOT;
        if(version > 2261)
            flags |= PATCH_CALL_SETENV;
    } else {
        ERROR("[%s] unknown image", __FUNCTION__);
        goto end;
    }
    
    uint32_t iboot_base = find_iboot_base(buf, sz);
    LOG("[%s] iboot_base: %08x", __FUNCTION__, iboot_base);
    
    if(flags & PATCH_RSA) {
        uint32_t verify_shsh = find_verify_shsh(buf, sz);
        LOG("[%s] verify_shsh: %08x", __FUNCTION__, verify_shsh);
        if(verify_shsh)
            if(write32(buf, sz, verify_shsh, 0x60182000))
                goto end;
    }
    
    if(flags & PATCH_DEBUG) {
        uint32_t debug_patch = find_debug_enabled(iboot_base, buf, sz);
        LOG("[%s] debug_enabled: %08x", __FUNCTION__, debug_patch);
        if(debug_patch)
            if(write32(buf, sz, debug_patch, 0xbf002001))
                goto end;
    }
    
    // todo
    if(flags & PATCH_TICKET) {
        uint32_t ticket_patch1 = find_ticket1(iboot_base, buf, sz);
        uint32_t ticket_patch2 = find_ticket2(iboot_base, buf, sz);
        LOG("[%s] ticket_patch1: %08x", __FUNCTION__, ticket_patch1); // replace: mov r0, #0, mov r1, #0
        LOG("[%s] ticket_patch2: %08x", __FUNCTION__, ticket_patch2);
        if(ticket_patch1 && ticket_patch2 && (ticket_patch2>ticket_patch1) && (ticket_patch2 - ticket_patch1 > 8)) {
            if(write32(buf, sz, ticket_patch1 + 0x00, 0x0000f04f))
                goto end;
            if(write32(buf, sz, ticket_patch1 + 0x04, 0x0100f04f))
                goto end;
            
            for(int i=8; i<(ticket_patch2 - ticket_patch1); i+=2) {
                if(write16(buf, sz, ticket_patch1 + i, 0xbf00))
                    goto end;
            }
            
            if((*(uint32_t*)(buf + ticket_patch2) == 0x30fff04f) && insn_is_32bit((uint16_t*)(buf + ticket_patch2)))
                if(write32(buf, sz, ticket_patch2, 0x0000f04f))
                    goto end;
            
        }
    }
    
    if(flags & PATCH_BOOT_PARTITION) {
        uint32_t boot_partition = find_boot_partition(iboot_base, buf, sz);
        LOG("[%s] boot_partition: %08x", __FUNCTION__, boot_partition);
        if(boot_partition)
            if(write32(buf, sz, boot_partition, 0xbf002000))
                goto end;
    }
    
    if(flags & PATCH_BOOT_RAMDISK) {
        uint32_t boot_ramdisk = find_boot_ramdisk(iboot_base, buf, sz);
        LOG("[%s] boot_ramdisk: %08x", __FUNCTION__, boot_ramdisk);
        if(boot_ramdisk)
            if(write32(buf, sz, boot_ramdisk, 0xbf002000))
                goto end;
    }
    
    if(flags & PATCH_CALL_SETENV) {
        uint32_t sys_setup_default_environment = find_sys_setup_default_environment(iboot_base, buf, sz);
        LOG("[%s] sys_setup_default_environment: %08x", __FUNCTION__, sys_setup_default_environment);
        if(sys_setup_default_environment)
            if(write32(buf, sz, sys_setup_default_environment, 0xbf00bf00))
                goto end;
    }
    
    if(flags & PATCH_GO_CMD_HANDLER) {
        uint32_t loadaddr = 0;
        if(iboot_base < 0x60000000)
            loadaddr = 0x40000000;
        else
            loadaddr = 0x80000000;
        
        uint32_t ptr = find_go_cmd_handler(iboot_base, buf, sz);
        LOG("[%s] go_cmd handler: %08x", __FUNCTION__, ptr);
        if(ptr) {
            if(write32(buf, sz, ptr, loadaddr))
                goto end;
        }
    }
    
    if(flags & PATCH_BOOTARGS) {
        uint32_t boot_args_null = find_boot_args_null_xref(iboot_base, buf, sz);
        LOG("[%s] boot_args_null: %08x", __FUNCTION__, boot_args_null);
        uint32_t boot_args = find_boot_args_xref(iboot_base, buf, sz);
        LOG("[%s] boot_args: %08x", __FUNCTION__, boot_args);
        uint32_t reliance_str = find_reliance_str(iboot_base, buf, sz);
        LOG("[%s] reliance_str: %08x", __FUNCTION__, reliance_str);
        
        if(boot_args_null && boot_args && reliance_str) {
            if(reliance_str+MAX_BOOTARGS_LEN > sz) {
                ERROR("[%s] overflow", __FUNCTION__);
                goto end;
            }
            
            char str[MAX_BOOTARGS_LEN];
            memset(&str, 0x0, MAX_BOOTARGS_LEN);
            
            if(customBootArgs) {
                if((strlen(customBootArgs))+1 > MAX_BOOTARGS_LEN) {
                    ERROR("[%s] customBootArgs is too large!", __FUNCTION__);
                    goto end;
                }
                sprintf(str, "%s", customBootArgs);
            }
            
            if(flags & PATCH_RAMDISK_BOOT) {
                if((strlen(str) + strlen(RAMDISK_BOOT))+1 > MAX_BOOTARGS_LEN) {
                    ERROR("[%s] bootArgs is too large!", __FUNCTION__);
                    goto end;
                }
                if(customBootArgs)
                    sprintf(str, "%s %s", str, RAMDISK_BOOT);
                else
                    sprintf(str, "%s", RAMDISK_BOOT);
            }
            
            if(customBootArgs || (flags & PATCH_RAMDISK_BOOT)) {
                LOG("[%s] bootArgs: %s", __FUNCTION__, str);
                memcpy(buf+reliance_str, str, strlen(str)+1);
                if(write32(buf, sz, boot_args_null, iboot_base + reliance_str))
                    goto end;
                if(write32(buf, sz, boot_args, iboot_base + reliance_str))
                    goto end;
            }
        }
    }
    
    
    // write
    LOG("[%s] writing buf", __FUNCTION__);
    outFile->write(outFile, buf, sz);
    outFile->close(outFile);
    inFile->close(inFile);
    free(buf);
    return 0;
    
end:
    inFile->close(inFile);
    outFile->close(outFile);
    free(buf);
    
    return -1;
    
}

int doiBootPatch(StringValue* fileValue, const char* bundlePath, OutputState** state, unsigned int* key, unsigned int* iv, int useMemory, const char* bootArgs, uint32_t debugFlags)
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
    
    if(patchiBoot(file, out, bootArgs, debugFlags) != 0) {
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

int patchiBootFromAbstractFile(AbstractFile* inFile, AbstractFile* tmpFile, unsigned char** outBuf, size_t* outSize, unsigned int* iv, unsigned int* key)
{
    unsigned char* buffer;
    size_t bufferSize;
    AbstractFile* outRaw;
    
    AbstractFile* file;
    AbstractFile* out;
    
    {
        bufferSize = 0;
        buffer = malloc(1);
        outRaw = createAbstractFileFromMemoryFile((void**)&buffer, &bufferSize);
    }
    
    if(!inFile || !tmpFile || !outRaw)
        return -1;
    
    {
        if(key) {
            out = duplicateAbstractFile2(tmpFile, outRaw, key, iv, NULL);
        } else {
            out = duplicateAbstractFile(tmpFile, outRaw);
        }
        
        if(key) {
            file = openAbstractFile2(inFile, key, iv);
        } else {
            file = openAbstractFile(inFile);
        }
    }
    
    if(!file || !out)
        return -1;
    
    if(patchiBoot(file, out, NULL, PATCH_NONE) != 0)
        return -1;
    
    *outBuf = buffer;
    *outSize = bufferSize;
    return 0;
}
