#ifndef IBOOT_H
#define IBOOT_H

#include <abstractfile.h>
#include <patchfinder.h>

#include <xpwn/libxpwn.h>
#include <xpwn/outputstate.h>
#include <xpwn/pwnutil.h>
#include <xpwn/nor_files.h>

#define PATCH_NONE              (0)
#define PATCH_RSA               (1 << 1)
#define PATCH_DEBUG             (1 << 2)
#define PATCH_TICKET            (1 << 3)
#define PATCH_BOOT_PARTITION    (1 << 4)
#define PATCH_BOOT_RAMDISK      (1 << 5)
#define PATCH_CALL_SETENV       (1 << 6)
#define PATCH_BOOTARGS          (1 << 7)
#define PATCH_RAMDISK_BOOT      (1 << 8)
#define PATCH_GO_CMD_HANDLER    (1 << 9)

#define DEFAULT_BOOTARGS    ""
#define CSBYPASS_BOOTARGS   "cs_enforcement_disable=1 amfi_get_out_of_my_way=1"
#define RAMDISK_BOOT        "-progress rd=md0 nand-enable-reformat=1"
#define MAX_BOOTARGS_LEN    128

int patchiBoot(AbstractFile* inFile, AbstractFile* outFile, const char* customBootArgs, uint32_t debugFlags);
int doiBootPatch(StringValue* fileValue, const char* bundlePath, OutputState** state, unsigned int* key, unsigned int* iv, int useMemory, const char* bootArgs, uint32_t debugFlags);
int patchiBootFromAbstractFile(AbstractFile* inFile, AbstractFile* tmpFile, unsigned char** outBuf, size_t* outSize, unsigned int* iv, unsigned int* key);

#endif
