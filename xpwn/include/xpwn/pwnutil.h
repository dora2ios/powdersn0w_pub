#ifndef PWNUTIL_H
#define PWNUTIL_H

#include <xpwn/plist.h>
#include <xpwn/outputstate.h>
#include <hfs/hfsplus.h>

typedef int (*PatchFunction)(AbstractFile* file);

#ifdef __cplusplus
extern "C" {
#endif
    int patch(AbstractFile* in, AbstractFile* out, AbstractFile* patch);
    Dictionary* openDict(const char* plistPath);
    Dictionary* parseIPSW(const char* inputIPSW, const char* bundleRoot, char** bundlePath, OutputState** state);
    Dictionary* parseIPSW2(const char* inputIPSW, const char* bundleRoot, char** bundlePath, OutputState** state, int useMemory);
    Dictionary* parseIPSW3(const char* inputIPSW, const char* bundleRoot, char** bundlePath, OutputState** state, int useMemory);
    int doPatch(StringValue* patchValue, StringValue* fileValue, const char* bundlePath, OutputState** state, unsigned int* key, unsigned int* iv, int useMemory, int isPlain);
    int doDecrypt(StringValue* decryptValue, StringValue* fileValue, const char* bundlePath, OutputState** state, unsigned int* key, unsigned int* iv, int useMemory);
    void doPatchInPlace(Volume* volume, const char* filePath, const char* patchPath);
    void doPatchInPlaceMemoryPatch(Volume* volume, const char* filePath, void** patch, size_t* patchSize);
    void createRestoreOptions(Volume* volume, const char *optionsPlist, int SystemPartitionSize, int UpdateBaseband);
    int mergeIdentities(Dictionary* manifest, AbstractFile *idFile);
    
#ifdef __cplusplus
}
#endif

#endif
