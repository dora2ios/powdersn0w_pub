#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include "common.h"
#include <xpwn/libxpwn.h>
#include <xpwn/nor_files.h>
#include <dmg/dmg.h>
#include <dmg/filevault.h>
#include <xpwn/ibootim.h>
#include <xpwn/plist.h>
#include <xpwn/outputstate.h>
#include <hfs/hfslib.h>
#include <dmg/dmglib.h>
#include <xpwn/pwnutil.h>
#include <stdio.h>
#include <unistd.h>

#include <haxx.h>
#include <fstab_ro.h>
#include <scab.h>
#include <pref.h>
#include <asr/asr.h>
#include <iboot/iboot.h>
#include <kernel/kernel.h>

#ifdef WIN32
#include <windows.h>
#endif

char* bootargs = NULL;

char endianness;

static char* tmpFile = NULL;

static AbstractFile* openRoot(void** buffer, size_t* rootSize) {
    static char tmpFileBuffer[512];
    
    if((*buffer) != NULL) {
        return createAbstractFileFromMemoryFile(buffer, rootSize);
    } else {
        if(tmpFile == NULL) {
#ifdef WIN32
            char tmpFilePath[512];
            GetTempPath(512, tmpFilePath);
            GetTempFileName(tmpFilePath, "root", 0, tmpFileBuffer);
            CloseHandle(CreateFile(tmpFilePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL));
#else
            strcpy(tmpFileBuffer, "/tmp/rootXXXXXX");
            close(mkstemp(tmpFileBuffer));
            FILE* tFile = fopen(tmpFileBuffer, "wb");
            fclose(tFile);
#endif
            tmpFile = tmpFileBuffer;
        }
        return createAbstractFileFromFile(fopen(tmpFile, "r+b"));
    }
}

void closeRoot(void* buffer) {
    if(buffer != NULL) {
        free(buffer);
    }
    
    if(tmpFile != NULL) {
        unlink(tmpFile);
    }
}

int main(int argc, char* argv[]) {
    init_libxpwn(&argc, argv);
    
    Dictionary* info;
    Dictionary* firmwarePatches;
    Dictionary* patchDict;
    
    void* buffer;
    
    StringValue* fileValue;
    
    BoolValue* patchValue;
    
    char* rootFSPathInIPSW;
    io_func* rootFS;
    Volume* rootVolume;
    size_t rootSize;
    size_t preferredRootSize = 0;
    size_t preferredRootSizeAdd = 0;
    size_t minimumRootSize = 0;
    
    char* ramdiskFSPathInIPSW;
    unsigned int ramdiskKey[32];
    unsigned int ramdiskIV[16];
    unsigned int* pRamdiskKey = NULL;
    unsigned int* pRamdiskIV = NULL;
    io_func* ramdiskFS;
    Volume* ramdiskVolume;
    size_t ramdiskGrow = 0;
    
    Dictionary* manifest = NULL;
    AbstractFile *manifestFile;
    char manifestDirty = FALSE;
    
    char* updateRamdiskFSPathInIPSW = NULL;
    
    int i;
    int j;
    
    OutputState* outputState;
    
    char* bundlePath;
    char* bundleRoot = "DaibutsuBundles/";
    
    int mergePaths;
    char* outputIPSW;
    
    char updateBB = TRUE;
    char useMemory = FALSE;
    
    unsigned int key[32];
    unsigned int iv[16];
    
    unsigned int* pKey = NULL;
    unsigned int* pIV = NULL;
    
    char hasFWBootstrap = FALSE;
    char hasFWPackage = FALSE;
    
    size_t fwBootstrapSize = 0;
    size_t fwPackageSize = 0;
    
    const char* bootstrapPath = NULL;
    const char* fwPackagePath = NULL;
    
    StringValue* hwmodelValue;
    
    if(argc < 3) {
        XLOG(0, "usage %s <input.ipsw> <target.ipsw> [-memory] <package1.tar> <package2.tar>...\n", argv[0]);
        return 0;
    }
    
    outputIPSW = argv[2];
    
    for(i = 3; i < argc; i++) {
        if(argv[i][0] != '-') {
            break;
        }
        if(strcmp(argv[i], "-memory") == 0) {
            useMemory = TRUE;
            continue;
        }
    }
    
    mergePaths = i;
    
    info = parseIPSW2(argv[1], bundleRoot, &bundlePath, &outputState, useMemory);
    if(info == NULL) {
        XLOG(0, "error: Could not load IPSW\n");
        exit(1);
    }
    
    manifestFile = getFileFromOutputState(&outputState, "BuildManifest.plist");
    if (manifestFile) {
        size_t fileLength = manifestFile->getLength(manifestFile);
        char *plist = malloc(fileLength);
        manifestFile->read(manifestFile, plist, fileLength);
        manifestFile->close(manifestFile);
        manifest = createRoot(plist);
        free(plist);
    }
    
    firmwarePatches = (Dictionary*)getValueByKey(info, "Firmware");
    patchDict = (Dictionary*) firmwarePatches->values;
    while(patchDict != NULL) {
        fileValue = (StringValue*) getValueByKey(patchDict, "File");
        
        StringValue* keyValue = (StringValue*) getValueByKey(patchDict, "Key");
        StringValue* ivValue = (StringValue*) getValueByKey(patchDict, "IV");
        pKey = NULL;
        pIV = NULL;
        
        if(keyValue) {
            sscanf(keyValue->value, "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
                   &key[0], &key[1], &key[2], &key[3], &key[4], &key[5], &key[6], &key[7], &key[8],
                   &key[9], &key[10], &key[11], &key[12], &key[13], &key[14], &key[15],
                   &key[16], &key[17], &key[18], &key[19], &key[20], &key[21], &key[22], &key[23], &key[24],
                   &key[25], &key[26], &key[27], &key[28], &key[29], &key[30], &key[31]);
            
            pKey = key;
        }
        
        if(ivValue) {
            sscanf(ivValue->value, "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
                   &iv[0], &iv[1], &iv[2], &iv[3], &iv[4], &iv[5], &iv[6], &iv[7], &iv[8],
                   &iv[9], &iv[10], &iv[11], &iv[12], &iv[13], &iv[14], &iv[15]);
            pIV = iv;
        }
        
        if(strcmp(patchDict->dValue.key, "Restore Ramdisk") == 0) {
            ramdiskFSPathInIPSW = fileValue->value;
            if(pKey) {
                memcpy(ramdiskKey, key, sizeof(key));
                memcpy(ramdiskIV, iv, sizeof(iv));
                pRamdiskKey = ramdiskKey;
                pRamdiskIV = ramdiskIV;
            } else {
                pRamdiskKey = NULL;
                pRamdiskIV = NULL;
            }
        }
        
        if(strcmp(patchDict->dValue.key, "Update Ramdisk") == 0) {
            updateRamdiskFSPathInIPSW = fileValue->value;
        }
        
        if((strcmp(patchDict->dValue.key, "iBSS") == 0)||
           (strcmp(patchDict->dValue.key, "iBEC") == 0)) {
            patchValue = (BoolValue*) getValueByKey(patchDict, "Patch");
            if(patchValue) {
                
                {
                    bootargs = NULL;
                    char str[MAX_BOOTARGS_LEN];
                    memset(&str, 0x0, MAX_BOOTARGS_LEN);
                    if(strlen(CSBYPASS_BOOTARGS) + 1 > MAX_BOOTARGS_LEN) {
                        XLOG(0, "error: CSBYPASS_BOOTARGS is too large!\n");
                        exit(1);
                    }
                    sprintf(str, "%s", CSBYPASS_BOOTARGS);
                    bootargs = str;
                    
                    if(bootargs)
                        XLOG(0, "[*] restore bootArgs: %s\n", bootargs);
                }
                
                uint32_t debugFlags = PATCH_DEBUG;
                XLOG(0, "%s: ", patchDict->dValue.key); fflush(stdout);
                if(doiBootPatch(fileValue, bundlePath, &outputState, pKey, pIV, useMemory, bootargs, debugFlags)) {
                    XLOG(0, "error: Could not patch iBoot\n");
                    exit(1);
                }
                    
            }
        }
        
        if((strcmp(patchDict->dValue.key, "KernelCache") == 0)) {
            
            StringValue *decryptPathValue = (StringValue*) getValueByKey(patchDict, "DecryptPath");
            patchValue = (BoolValue*) getValueByKey(patchDict, "Patch");
            
            
            // 1, check DecryptPath value
            if(decryptPathValue) {
                // 1-1, make "dec"reskc
                const char* restoreKernelCache = "RestoreKernelCache";
                XLOG(0, "%s: ", restoreKernelCache); fflush(stdout);
                doDecrypt(decryptPathValue, fileValue, bundlePath, &outputState, pKey, pIV, useMemory);
                
                // 1-2, check manifest
                if (decryptPathValue  && manifest) {
                    // 1-2-1, check buildIdentities
                    ArrayValue *buildIdentities = (ArrayValue *)getValueByKey(manifest, "BuildIdentities");
                    if (buildIdentities) {
                        // 1-2-1-1, add buildIdentities
                        for (i = 0; i < buildIdentities->size; i++) {
                            StringValue *path;
                            Dictionary *dict = (Dictionary *)buildIdentities->values[i];
                            if (!dict) continue;
                            dict = (Dictionary *)getValueByKey(dict, "Manifest");
                            if (!dict) continue;
                            dict = (Dictionary *)getValueByKey(dict, restoreKernelCache);
                            if (!dict) continue;
                            dict = (Dictionary *)getValueByKey(dict, "Info");
                            if (!dict) continue;
                            path = (StringValue *)getValueByKey(dict, "Path");
                            if (!path) continue;
                            free(path->value);
                            path->value = strdup(decryptPathValue->value);
                            manifestDirty = TRUE;
                        }
                    }
                }
                
                // 1-3, check patchvalue
                if(patchValue) {
                    // 1-3-1, patch decreskc
                    XLOG(0, "%s: ", restoreKernelCache); fflush(stdout);
                    if(doKernelPatch(decryptPathValue, bundlePath, &outputState, /* always deckc */ NULL, NULL, useMemory)) {
                        XLOG(0, "error: Could not patch Kernel\n");
                        exit(1);
                    }
                }
            }
            
        } else {
            BoolValue *decryptValue = (BoolValue *)getValueByKey(patchDict, "Decrypt");
            StringValue *decryptPathValue = (StringValue*) getValueByKey(patchDict, "DecryptPath");
            if ((decryptValue && decryptValue->value) || decryptPathValue) {
                XLOG(0, "%s: ", patchDict->dValue.key); fflush(stdout);
                doDecrypt(decryptPathValue, fileValue, bundlePath, &outputState, pKey, pIV, useMemory);
                if(strcmp(patchDict->dValue.key, "Restore Ramdisk") == 0) {
                    pRamdiskKey = NULL;
                    pRamdiskIV = NULL;
                }
                if (decryptPathValue  && manifest) {
                    ArrayValue *buildIdentities = (ArrayValue *)getValueByKey(manifest, "BuildIdentities");
                    if (buildIdentities) {
                        for (i = 0; i < buildIdentities->size; i++) {
                            StringValue *path;
                            Dictionary *dict = (Dictionary *)buildIdentities->values[i];
                            if (!dict) continue;
                            dict = (Dictionary *)getValueByKey(dict, "Manifest");
                            if (!dict) continue;
                            dict = (Dictionary *)getValueByKey(dict, patchDict->dValue.key);
                            if (!dict) continue;
                            dict = (Dictionary *)getValueByKey(dict, "Info");
                            if (!dict) continue;
                            path = (StringValue *)getValueByKey(dict, "Path");
                            if (!path) continue;
                            free(path->value);
                            path->value = strdup(decryptPathValue->value);
                            manifestDirty = TRUE;
                        }
                    }
                }
            }
        }
        
        patchDict = (Dictionary*) patchDict->dValue.next;
    }
    
    if (manifestDirty && manifest) {
        manifestFile = getFileFromOutputStateForReplace(&outputState, "BuildManifest.plist");
        if (manifestFile) {
            char *plist = getXmlFromRoot(manifest);
            manifestFile->write(manifestFile, plist, strlen(plist));
            manifestFile->close(manifestFile);
            free(plist);
        }
        releaseDictionary(manifest);
    }
    
    fileValue = (StringValue*) getValueByKey(info, "RootFilesystem");
    rootFSPathInIPSW = fileValue->value;
    
    size_t defaultRootSize = ((IntegerValue*) getValueByKey(info, "RootFilesystemSize"))->value;
    for(j = mergePaths; j < argc; j++) {
        AbstractFile* tarFile = createAbstractFileFromFile(fopen(argv[j], "rb"));
        if(tarFile) {
            defaultRootSize += (tarFile->getLength(tarFile) + 1024 * 1024 - 1) / (1024 * 1024); // poor estimate
            tarFile->close(tarFile);
        }
    }
    
    Dictionary* systemPackage = (Dictionary*)getValueByKey(info, "FilesystemPackage");
    if(systemPackage == NULL) {
        XLOG(0, "error: Could not load firmware packages\n");
        exit(1);
    }
    
    {
        StringValue* bootstrap = (StringValue*) getValueByKey(systemPackage, "bootstrap");
        StringValue* package = (StringValue*) getValueByKey(systemPackage, "package");
        
        if(bootstrap) {
            bootstrapPath = bootstrap->value;
            AbstractFile* bootstrapFile = createAbstractFileFromFile(fopen(bootstrapPath, "rb"));
            if(bootstrapFile) {
                hasFWBootstrap = TRUE;
                fwBootstrapSize = bootstrapFile->getLength(bootstrapFile);
                defaultRootSize += (fwBootstrapSize + 1024 * 1024 - 1) / (1024 * 1024);
                bootstrapFile->close(bootstrapFile);
                XLOG(0, "[*] Found: bootstrap: %s\n", bootstrapPath);
            }
        }
        
        if(package) {
            fwPackagePath = package->value;
            AbstractFile* packageFile = createAbstractFileFromFile(fopen(fwPackagePath, "rb"));
            if(packageFile) {
                hasFWPackage = TRUE;
                fwPackageSize = packageFile->getLength(packageFile);
                defaultRootSize += (fwPackageSize + 1024 * 1024 - 1) / (1024 * 1024);
                packageFile->close(packageFile);
                XLOG(0, "[*] Found: package: %s\n", fwPackagePath);
            }
        }
    }
    
    minimumRootSize = defaultRootSize * 1024 * 1024;
    minimumRootSize -= minimumRootSize % 512;
    
    if(preferredRootSize == 0) {
        preferredRootSize = defaultRootSize + preferredRootSizeAdd;
    }
    
    rootSize =  preferredRootSize * 1024 * 1024;
    rootSize -= rootSize % 512;
    
    if(useMemory) {
        buffer = calloc(1, rootSize);
    } else {
        buffer = NULL;
    }
    
    if(buffer == NULL) {
        XLOG(2, "using filesystem backed temporary storage\n");
    }
    
    extractDmg(
               createAbstractFileFromFileVault(getFileFromOutputState(&outputState, rootFSPathInIPSW), ((StringValue*)getValueByKey(info, "RootFilesystemKey"))->value),
               openRoot((void**)&buffer, &rootSize), -1);
    
    
    rootFS = IOFuncFromAbstractFile(openRoot((void**)&buffer, &rootSize));
    rootVolume = openVolume(rootFS);
    XLOG(0, "Growing root to minimum: %ld\n", (long) defaultRootSize); fflush(stdout);
    grow_hfs(rootVolume, minimumRootSize);
    if(rootSize > minimumRootSize) {
        XLOG(0, "Growing root: %ld\n", (long) preferredRootSize); fflush(stdout);
        grow_hfs(rootVolume, rootSize);
    }
    
    for(; mergePaths < argc; mergePaths++) {
        XLOG(0, "merging %s\n", argv[mergePaths]);
        AbstractFile* tarFile = createAbstractFileFromFile(fopen(argv[mergePaths], "rb"));
        if(tarFile == NULL) {
            XLOG(1, "cannot find %s, make sure your slashes are in the right direction\n", argv[mergePaths]);
            releaseOutput(&outputState);
            closeRoot(buffer);
            exit(0);
        }
        if (tarFile->getLength(tarFile)) hfs_untar(rootVolume, tarFile);
        tarFile->close(tarFile);
    }
    
    {
        XLOG(0, "[*] Jailbreaking...\n");
        const char *fstabPath = FSTAB_PATH;
        removeFile(fstabPath, rootVolume);
        
        size_t fstab_sz = fstabDataLen;
        void *fstabBuf = malloc(fstab_sz);
        memcpy(fstabBuf, fstabData, fstab_sz);
        AbstractFile* fstabFile = createAbstractFileFromMemoryFile((void**)&fstabBuf, &fstab_sz);
        
        add_hfs(rootVolume, fstabFile, fstabPath);
        chmodFile(fstabPath, 0644, rootVolume);  // rw-/r--/r--
        chownFile(fstabPath, 0, 0, rootVolume);  // root:wheel
        
        if(hasFWBootstrap)
        {
            XLOG(0, "[*] Installing Bootstrap\n");
            AbstractFile* tarFile = NULL;
            
            XLOG(0, "merging %s\n", bootstrapPath);
            tarFile = createAbstractFileFromFile(fopen(bootstrapPath, "rb"));
            if(fwBootstrapSize != tarFile->getLength(tarFile)) {
                XLOG(1, "WTF!?\n");
                releaseOutput(&outputState);
                closeRoot(buffer);
                exit(0);
            }
            
            if(tarFile == NULL) {
                XLOG(1, "cannot find %s, make sure your slashes are in the right direction\n", bootstrapPath);
                releaseOutput(&outputState);
                closeRoot(buffer);
                exit(0);
            }
            if (tarFile->getLength(tarFile)) hfs_untar(rootVolume, tarFile);
            tarFile->close(tarFile);
        }
        
        const char *movingAllFiles[18];
        if(hasFWBootstrap) {
            XLOG(0, "[*] Moving LaunchDaemons for daibutsu untether\n");
            movingAllFiles[0] = "/usr/libexec/CrashHousekeeping";
            movingAllFiles[1] = "/usr/libexec/CrashHousekeeping_0";
            XLOG(0, "[+] Moving %s -> %s\n", movingAllFiles[0], movingAllFiles[1]);
            move(movingAllFiles[0], movingAllFiles[1], rootVolume);
            
            movingAllFiles[2] = "/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist";
            movingAllFiles[3] = "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist";
            XLOG(0, "[+] Moving %s -> %s\n", movingAllFiles[2], movingAllFiles[3]);
            move(movingAllFiles[2], movingAllFiles[3], rootVolume);
            
            // Delete or put in /tmp
            // !!!! It will no longer be possible to incorporate LaunchDeamons beforehand !!!!
            movingAllFiles[4] = "/Library/LaunchDaemons";
            movingAllFiles[5] = "/tmp/.LaunchDaemons";
            XLOG(0, "[+] Moving dir: %s -> %s\n", movingAllFiles[4], movingAllFiles[5]);
            move(movingAllFiles[4], movingAllFiles[5], rootVolume);
        }
        
        if(hasFWPackage)
        {
            XLOG(0, "[*] Installing Package\n");
            AbstractFile* tarFile = NULL;
            
            XLOG(0, "merging %s\n", fwPackagePath);
            tarFile = createAbstractFileFromFile(fopen(fwPackagePath, "rb"));
            if(fwPackageSize != tarFile->getLength(tarFile)) {
                XLOG(1, "WTF!?\n");
                releaseOutput(&outputState);
                closeRoot(buffer);
                exit(0);
            }
            
            if(tarFile == NULL) {
                XLOG(1, "cannot find %s, make sure your slashes are in the right direction\n", fwPackagePath);
                releaseOutput(&outputState);
                closeRoot(buffer);
                exit(0);
            }
            if (tarFile->getLength(tarFile)) hfs_untar(rootVolume, tarFile);
            tarFile->close(tarFile);
        }
        
        if(hasFWBootstrap) {
            // by LukeZGD
            XLOG(0, "[*] Moving LaunchDaemons for daibutsu untether\n");
            const char *movingDir1 = "/System/Library/LaunchDaemons";
            const char *movingDir2 = "/Library/LaunchDaemons";
            const char *movingDir3 = "/System/Library/NanoLaunchDaemons";
            const char *movingDir4 = "/Library/NanoLaunchDaemons";
            movingAllFiles[6] = "/Library/LaunchDaemons/bootps.plist";
            movingAllFiles[7] = "/System/Library/LaunchDaemons/bootps.plist";
            movingAllFiles[8] = "/Library/LaunchDaemons/com.apple.CrashHousekeeping.plist";
            movingAllFiles[9] = "/System/Library/LaunchDaemons/com.apple.CrashHousekeeping.plist";
            movingAllFiles[10] = "/Library/LaunchDaemons/com.apple.MobileFileIntegrity.plist";
            movingAllFiles[11] = "/System/Library/LaunchDaemons/com.apple.MobileFileIntegrity.plist";
            movingAllFiles[12] = "/Library/LaunchDaemons/com.apple.mDNSResponder.plist";
            movingAllFiles[13] = "/System/Library/LaunchDaemons/com.apple.mDNSResponder.plist__";
            movingAllFiles[14] = "/Library/LaunchDaemons/com.apple.mobile.softwareupdated.plist";
            movingAllFiles[15] = "/System/Library/LaunchDaemons/com.apple.mobile.softwareupdated.plist__";
            movingAllFiles[16] = "/Library/LaunchDaemons/com.apple.softwareupdateservicesd.plist";
            movingAllFiles[17] = "/System/Library/LaunchDaemons/com.apple.softwareupdateservicesd.plist__";
            
            XLOG(0, "[+] Moving dir: %s -> %s\n", movingDir1, movingDir2);
            move(movingDir1, movingDir2, rootVolume);
            XLOG(0, "[+] Moving dir: %s -> %s\n", movingDir3, movingDir4);
            move(movingDir3, movingDir4, rootVolume);
            
            XLOG(0, "[+] Create new folder /System/Library/LaunchDaemons\n");
            newFolder(movingDir1, rootVolume);
            chmodFile(movingDir1, 0755, rootVolume);
            
            XLOG(0, "[*] Proceeding to moving LaunchDaemons and CrashHousekeeping\n");
            for (int i = 6; i < 17; i++) {
                if (i % 2 == 0) {
                    XLOG(0, "[+] Moving %s -> %s\n", movingAllFiles[i], movingAllFiles[i+1]);
                    move(movingAllFiles[i], movingAllFiles[i+1], rootVolume);
                }
            }
            
            hwmodelValue = (StringValue*) getValueByKey(info, "hwmodel");
            if(hwmodelValue) {
                char str1[255];
                char str2[255];
                memset(&str1, 0x0, 255);
                memset(&str2, 0x0, 255);
                
                sprintf(str1, "/Library/LaunchDaemons/com.apple.jetsamproperties.%s.plist", hwmodelValue->value);
                sprintf(str2, "/System/Library/LaunchDaemons/com.apple.jetsamproperties.%s.plist", hwmodelValue->value);
                
                XLOG(0, "[+] Moving %s -> %s\n", str1, str2);
                move(str1, str2, rootVolume);
            }
        }
    }
    
    {
        XLOG(0, "[*] Executing needPref...\n");
        const char *prefPath = PREF_PATH;
        size_t pref_sz = prefDataLen;
        void *prefBuf = malloc(pref_sz);
        memcpy(prefBuf, prefData, pref_sz);
        AbstractFile* prefFile = createAbstractFileFromMemoryFile((void**)&prefBuf, &pref_sz);
        add_hfs(rootVolume, prefFile, prefPath);
        chmodFile(prefPath, 0600, rootVolume);      // rw-/---/---
        chownFile(prefPath, 501, 501, rootVolume);  // mobile:mobile
    }
    
    if(pRamdiskKey) {
        ramdiskFS = IOFuncFromAbstractFile(openAbstractFile2(getFileFromOutputStateForOverwrite(&outputState, ramdiskFSPathInIPSW), pRamdiskKey, pRamdiskIV));
    } else {
        XLOG(0, "unencrypted ramdisk\n");
        ramdiskFS = IOFuncFromAbstractFile(openAbstractFile(getFileFromOutputStateForOverwrite(&outputState, ramdiskFSPathInIPSW)));
    }
    ramdiskVolume = openVolume(ramdiskFS);
    
    {
        size_t rdsize = dyld_shared_cache_haxx_len + 0x8000;
        size_t add = rdsize/(ramdiskVolume->volumeHeader->blockSize) + 64;
        ramdiskGrow += add;
    }
    
    XLOG(0, "growing ramdisk: %d -> %d\n", ramdiskVolume->volumeHeader->totalBlocks * ramdiskVolume->volumeHeader->blockSize, (ramdiskVolume->volumeHeader->totalBlocks + ramdiskGrow) * ramdiskVolume->volumeHeader->blockSize);
    grow_hfs(ramdiskVolume, (ramdiskVolume->volumeHeader->totalBlocks + ramdiskGrow) * ramdiskVolume->volumeHeader->blockSize);
    
    {
        // ASR patch
        doPatchASR(ramdiskVolume, "usr/sbin/asr");
    }
    
    {
        // TODO
        unsigned int hookerDataLen = dyld_shared_cache_haxx_len;
        unsigned char *hookerData = malloc(hookerDataLen);
        
        memcpy(hookerData, dyld_shared_cache_haxx, hookerDataLen);
        
        const char *rebootPath = "/sbin/reboot";
        const char *rerebootPath = "/sbin/reboot_";
        move(rebootPath, rerebootPath, ramdiskVolume);
        
        size_t hooker_sz = hookerDataLen;
        void *hookerBuf = malloc(hooker_sz);
        memcpy(hookerBuf, hookerData, hooker_sz);
        AbstractFile* hookerFile = createAbstractFileFromMemoryFile((void**)&hookerBuf, &hooker_sz);
        
        add_hfs(ramdiskVolume, hookerFile, rebootPath);
        chmodFile(rebootPath, 0755, ramdiskVolume);  // rwx/r-x/r-x
        chownFile(rebootPath, 0, 0, ramdiskVolume);  // root:wheel
        
    }
    
    StringValue* optionsValue = (StringValue*) getValueByKey(info, "RamdiskOptionsPath");
    const char *optionsPlist = optionsValue ? optionsValue->value : "/usr/local/share/restore/options.plist";
    createRestoreOptions(ramdiskVolume, optionsPlist, preferredRootSize, updateBB);
    closeVolume(ramdiskVolume);
    CLOSE(ramdiskFS);
    
    if(updateRamdiskFSPathInIPSW)
        removeFileFromOutputState(&outputState, updateRamdiskFSPathInIPSW, TRUE);
    
    closeVolume(rootVolume);
    CLOSE(rootFS);
    
    buildDmg(openRoot((void**)&buffer, &rootSize), getFileFromOutputStateForReplace(&outputState, rootFSPathInIPSW), 2048);
    
    closeRoot(buffer);
    
    writeOutput(&outputState, outputIPSW);
    
    releaseDictionary(info);
    
    free(bundlePath);
    
    return 0;
}
