#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include <mach-o/loader.h>
#include <openssl/sha.h>

#include <abstractfile.h>
#include <xpwn/libxpwn.h>
#include <xpwn/nor_files.h>
#include <hfs/hfslib.h>

#include <patchfinder.h>

static bool debug_enabled = true;
#define ERROR(x, ...)             do { printf("\x1b[31m[ERROR] "x"\x1b[39m\n", ##__VA_ARGS__); } while(0)
#define DEBUGLOG(x, ...)          do { if(debug_enabled) printf("\x1b[34m"x"\x1b[39m\n", ##__VA_ARGS__); } while(0)
#define LOG(x, ...)               do { printf("\x1b[32m"x"\x1b[39m\n", ##__VA_ARGS__); } while(0)

struct CodeDirectory {
    uint32_t magic;
    uint32_t length;
    uint32_t version;
    uint32_t flags;
    uint32_t hashOffset;
    uint32_t identOffset;
    uint32_t nSpecialSlots;
    uint32_t nCodeSlots;
    uint32_t codeLimit;
    uint8_t hashSize;
    uint8_t hashType;
    uint8_t platform;
    uint8_t pageSize;
    /* ... */
};

struct CodeHash {
    unsigned char hash[SHA_DIGEST_LENGTH];
};

static uint32_t swap32(uint32_t val)
{
    return ((val&~0xffffff00)<<24) | (((val>>8)&~0xffff00)<<16) | (((val>>16)&~0xff00)<<8) | (val>>24);
}

static int validateHash(unsigned char *pageHash, unsigned char *hash)
{
    bool equal = true;
    int i = 0;
    
    char pageHashStr[128];
    memset(&pageHashStr, 0x0, 128);
    char hashStr[128];
    memset(&hashStr, 0x0, 128);
    
    for(i=0;i<SHA_DIGEST_LENGTH;i++){
        sprintf(pageHashStr, "%s%02x", pageHashStr, pageHash[i]);
    }
    
    for(i=0;i<SHA_DIGEST_LENGTH;i++){
        sprintf(hashStr, "%s%02x", hashStr, hash[i]);
    }
    
    for(i=0;i<SHA_DIGEST_LENGTH;i++){
        if(pageHash[i] != hash[i]) {
            equal = false;
            hash[i] = pageHash[i];
        }
    }
    
    if(equal != true)
        DEBUGLOG("[%s] %s %s %s", __FUNCTION__, pageHashStr, equal == true ? "==" : "!=", hashStr);
    
    return 0;
}

static uint32_t OFFSET(uint32_t base, uint32_t off)
{
    if(!off) {
        //DEBUGLOG("Failed to get koffset");
        return 0;
    }
    //DEBUGLOG("%08x", base+off);
    return base+off;
}

int patchASR(AbstractFile* inFile, AbstractFile* outFile)
{
    unsigned char* buf = NULL;
    size_t sz = 0;
    uint32_t text_base = 0;
    int i = 0;
    
    sz = (size_t) inFile->getLength(inFile);
    buf = (unsigned char*) malloc(sz);
    inFile->read(inFile, buf, sz);
    
    LOG("");
    
    LOG("[%s] sz: %zx", __FUNCTION__, sz);
    
    // search
    uint32_t max = 0;
    uint32_t min = -1;
    size_t size = 0;
    uint32_t text_vmaddr = 0;
    uint32_t text_vmsize = 0;
    uint32_t cs_start = 0;
    const struct mach_header *hdr = (struct mach_header *)buf;
    DEBUGLOG("[%s] magic: %x", __FUNCTION__, hdr->magic);
    if(hdr->magic != MH_MAGIC) {
        ERROR("[%s] unkown magic!", __FUNCTION__);
        goto end;
    }
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
                text_vmaddr = seg->vmaddr;
                text_vmsize = seg->vmsize;
                DEBUGLOG("[%s] text_vmaddr: %x", __FUNCTION__, text_vmaddr);
            }
        } else if (cmd->cmd == LC_CODE_SIGNATURE) {
            // TODO
            const struct linkedit_data_command *seg = (struct linkedit_data_command *)q;
            DEBUGLOG("[%s] cmdsize: %08x", __FUNCTION__, seg->cmdsize);
            DEBUGLOG("[%s] dataoff: %08x", __FUNCTION__, seg->dataoff);
            DEBUGLOG("[%s] datasize: %d", __FUNCTION__, seg->datasize);
            cs_start = seg->dataoff;
        }
        q = q + cmd->cmdsize;
    }
    size = max - min; // unused..?
    
    text_base = text_vmaddr;
    LOG("[%s] text_base: %08x", __FUNCTION__, text_base);
    
    // offsetfinder
    uint32_t image_passed_signature = find_image_passed_signature(text_base, buf, sz);
    if(OFFSET(text_base, image_passed_signature) == 0) {
        ERROR("[%s] faild to get image_passed_signature", __FUNCTION__);
        goto end;
    }
    LOG("[%s] image_passed_signature: %08x", __FUNCTION__, OFFSET(text_base, image_passed_signature));
    
    uint32_t image_failed_signature = find_image_failed_signature(text_base, buf, sz);
    if(OFFSET(text_base, image_failed_signature) == 0) {
        ERROR("[%s] faild to get image_failed_signature", __FUNCTION__);
        goto end;
    }
    LOG("[%s] image_failed_signature: %08x", __FUNCTION__, OFFSET(text_base, image_failed_signature));
    
    if(OFFSET(text_base, image_passed_signature) == OFFSET(text_base, image_failed_signature)) {
        ERROR("[%s] WTF!?", __FUNCTION__);
        goto end;
    }
    
    uint32_t bl_insn = make_b_w(image_failed_signature, image_passed_signature);
    
    // patch
    if(bl_insn == -1) {
        ERROR("[%s] unkown insn!", __FUNCTION__);
        goto end;
    }
    *(uint32_t*)(buf + image_failed_signature) = bl_insn;
    LOG("[%s] patched: %08x: %08x", __FUNCTION__, image_failed_signature, bl_insn);
    
    
    // TODO: Improve incomplete codes
    // search codeDirectory starts
    uint32_t csdir_start = buggy_find_csdir_magic(text_base, buf, sz);
    LOG("[%s] csdir_start: %08x", __FUNCTION__, csdir_start);
    const struct CodeDirectory *codeDirectory = (struct CodeDirectory *)(buf + csdir_start);
    
    DEBUGLOG("[%s] hashOffset: %x", __FUNCTION__, swap32(codeDirectory->hashOffset));          // nCodeSlot start: csdir_start + hashOffset
    DEBUGLOG("[%s] nSpecialSlots: %x", __FUNCTION__, swap32(codeDirectory->nSpecialSlots));    // TODO
    DEBUGLOG("[%s] nCodeSlots: %x", __FUNCTION__, swap32(codeDirectory->nCodeSlots));          //
    DEBUGLOG("[%s] codeLimit: %x", __FUNCTION__, swap32(codeDirectory->codeLimit));            //
    DEBUGLOG("[%s] hashSize: %x", __FUNCTION__, codeDirectory->hashSize);                      // 0x20
    DEBUGLOG("[%s] hashType: %x", __FUNCTION__, codeDirectory->hashType);                      // SHA-1
    DEBUGLOG("[%s] pageSize: %x", __FUNCTION__, 1 << codeDirectory->pageSize);                 // 0x1000
    
    size_t codeLimit = swap32(codeDirectory->codeLimit);
    size_t hashOffset = swap32(codeDirectory->hashOffset);
    struct CodeHash *codeHash = (struct CodeHash *)(buf + csdir_start + hashOffset); // nCodeSlot start
    
    unsigned char pageHash[SHA_DIGEST_LENGTH];
    
    unsigned char *pageBuf = NULL;
    size_t pageSize = 1 << codeDirectory->pageSize;
    if(pageSize > 0x10000) {
        ERROR("[%s] pagesize too large", __FUNCTION__);
        goto end;
    }
    
    pageBuf = malloc(pageSize);
    
    // bzero
    memset(pageBuf, 0x0, pageSize);
    
    SHA_CTX c;
    size_t p;
    
    // TODO: Improve incomplete codes
    // check: nCodeSlots only
    LOG("[%s] checking cs slots...", __FUNCTION__);
    for(p=0;p<codeLimit;p+=pageSize){
        // bzero
        memset(pageBuf, 0x0, pageSize);
        if(p+pageSize < codeLimit)
            memcpy(pageBuf, buf+p, pageSize);
        else
            memcpy(pageBuf, buf+p, codeLimit-p);
        
        SHA1_Init(&c);
        if(p+pageSize < codeLimit)
            SHA1_Update(&c, pageBuf, pageSize);
        else
            SHA1_Update(&c, pageBuf, codeLimit-p);
        SHA1_Final(pageHash, &c);
        
        // check and fix cs slot...
        validateHash(pageHash, codeHash->hash);
        
        // push 1-slot
        codeHash += 1;
    }
    
    // write
    LOG("[%s] writing buf", __FUNCTION__);
    outFile->write(outFile, buf, sz);
    outFile->close(outFile);
    free(buf);
    return 0;
    
end:
    inFile->close(inFile);
    outFile->close(outFile);
    free(buf);
    return -1;
}

void doPatchASR(Volume* volume, const char* filePath)
{
    void* buffer;
    void* buffer2;
    size_t bufferSize;
    size_t bufferSize2;
    AbstractFile* bufferFile;
    AbstractFile* out;
    
    buffer = malloc(1);
    bufferSize = 0;
    bufferFile = createAbstractFileFromMemoryFile((void**)&buffer, &bufferSize);
    
    XLOG(0, "retrieving..."); fflush(stdout);
    get_hfs(volume, filePath, bufferFile);
    bufferFile->close(bufferFile);
    
    XLOG(0, "patching..."); fflush(stdout);
    
    buffer2 = malloc(1);
    bufferSize2 = 0;
    out = duplicateAbstractFile(createAbstractFileFromMemoryFile((void**)&buffer, &bufferSize), createAbstractFileFromMemoryFile((void**)&buffer2, &bufferSize2));
    
    // reopen the inner package
    bufferFile = openAbstractFile(createAbstractFileFromMemoryFile((void**)&buffer, &bufferSize));
    
    if(!bufferFile || !out) {
        XLOG(0, "file error\n");
        exit(0);
    }
    
    if(patchASR(bufferFile, out) != 0) {
        XLOG(0, "patch failed\n");
        exit(0);
    }
    
    XLOG(0, "writing... "); fflush(stdout);
    add_hfs(volume, createAbstractFileFromMemoryFile((void**)&buffer2, &bufferSize2), filePath);
    free(buffer2);
    free(buffer);
    
    XLOG(0, "success\n"); fflush(stdout);
}
