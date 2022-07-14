#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <openssl/sha.h>
#include <xpwn/libxpwn.h>
#include <xpwn/plist.h>
#include <xpwn/outputstate.h>
#include <xpwn/pwnutil.h>
#include <xpwn/nor_files.h>
#include <hfs/hfslib.h>

#define BUFFERSIZE (1024*1024)

Dictionary* openDict(const char* plistPath)
{
    Dictionary* info = NULL;
    AbstractFile* plistFile;
    char* plist;
    
    XLOG(0, "checking: %s\n", plistPath);
    
    if((plistFile = createAbstractFileFromFile(fopen(plistPath, "rb"))) != NULL) {
        plist = (char*) malloc(plistFile->getLength(plistFile));
        plistFile->read(plistFile, plist, plistFile->getLength(plistFile));
        plistFile->close(plistFile);
        info = createRoot(plist);
        free(plist);
    }
    
    return info;
}
    
Dictionary* parseIPSW(const char* inputIPSW, const char* bundleRoot, char** bundlePath, OutputState** state) {
    return parseIPSW2(inputIPSW, bundleRoot, bundlePath, state, FALSE);
}

Dictionary* parseIPSW2(const char* inputIPSW, const char* bundleRoot, char** bundlePath, OutputState** state, int useMemory) {
    Dictionary* info;
    char* infoPath;
    
    AbstractFile* plistFile;
    char* plist;
    FILE* inputIPSWFile;
    
    SHA256_CTX sha_ctx;
    char* buffer;
    int read;
    unsigned char hash[32];
    
    DIR* dir;
    struct dirent* ent;
    StringValue* plistSHA256String;
    unsigned int plistHash[32];
    int i;
    
    *bundlePath = NULL;
    
    inputIPSWFile = fopen(inputIPSW, "rb");
    if(!inputIPSWFile) {
        return NULL;
    }
    
    XLOG(0, "Hashing IPSW...\n");
    
    buffer = malloc(BUFFERSIZE);
    SHA256_Init(&sha_ctx);
    while(!feof(inputIPSWFile)) {
        read = fread(buffer, 1, BUFFERSIZE, inputIPSWFile);
        SHA256_Update(&sha_ctx, buffer, read);
    }
    SHA256_Final(hash, &sha_ctx);
    free(buffer);
    
    fclose(inputIPSWFile);
    
    XLOG(0, "Matching IPSW in %s... (%02x%02x%02x%02x...)\n", bundleRoot, (int) hash[0], (int) hash[1], (int) hash[2], (int) hash[3]);
    
    dir = opendir(bundleRoot);
    if(dir == NULL) {
        XLOG(1, "Bundles directory not found\n");
        return NULL;
    }
    
    while((ent = readdir(dir)) != NULL) {
        if(ent->d_name[0] == '.' && (ent->d_name[1] == '\0' || (ent->d_name[1] == '.' && ent->d_name[2] == '\0'))) {
            continue;
        }
        
        infoPath = (char*) malloc(sizeof(char) * (strlen(bundleRoot) + sizeof(PATH_SEPARATOR) + strlen(ent->d_name) + sizeof(PATH_SEPARATOR "Info.plist")));
        sprintf(infoPath, "%s" PATH_SEPARATOR "%s" PATH_SEPARATOR "Info.plist", bundleRoot, ent->d_name);
        XLOG(0, "checking: %s\n", infoPath);
        
        if((plistFile = createAbstractFileFromFile(fopen(infoPath, "rb"))) != NULL) {
            plist = (char*) malloc(plistFile->getLength(plistFile));
            plistFile->read(plistFile, plist, plistFile->getLength(plistFile));
            plistFile->close(plistFile);
            info = createRoot(plist);
            free(plist);
            
            plistSHA256String = (StringValue*)getValueByKey(info, "SHA256");
            if(plistSHA256String) {
                sscanf(plistSHA256String->value, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                       &plistHash[0], &plistHash[1], &plistHash[2], &plistHash[3], &plistHash[4],
                       &plistHash[5], &plistHash[6], &plistHash[7], &plistHash[8], &plistHash[9],
                       &plistHash[10], &plistHash[11], &plistHash[12], &plistHash[13], &plistHash[14],
                       &plistHash[15], &plistHash[16], &plistHash[17], &plistHash[18], &plistHash[19],
                       &plistHash[20], &plistHash[21], &plistHash[22], &plistHash[23], &plistHash[24],
                       &plistHash[25], &plistHash[26], &plistHash[27], &plistHash[28], &plistHash[29],
                       &plistHash[30], &plistHash[31]);
                
                for(i = 0; i < 32; i++) {
                    if(plistHash[i] != hash[i]) {
                        break;
                    }
                }
                
                if(i == 32) {
                    *bundlePath = (char*) malloc(sizeof(char) * (strlen(bundleRoot) + sizeof(PATH_SEPARATOR) + strlen(ent->d_name)));
                    sprintf(*bundlePath, "%s" PATH_SEPARATOR "%s", bundleRoot, ent->d_name);
                    
                    free(infoPath);
                    break;
                }
            }
            
            releaseDictionary(info);
        }
        
        free(infoPath);
    }
    
    closedir(dir);
    
    if(*bundlePath == NULL) {
        return NULL;
    }
    
    *state = loadZip2(inputIPSW, useMemory);
    
    return info;
}

Dictionary* parseIPSW3(const char* inputIPSW, const char* bundleRoot, char** bundlePath, OutputState** state, int useMemory)
{
    Dictionary* info;
    char* infoPath;
    
    AbstractFile* plistFile;
    char* plist;
    FILE* inputIPSWFile;
    
    SHA256_CTX sha_ctx;
    char* buffer;
    int read;
    unsigned char hash[32];
    
    DIR* dir;
    struct dirent* ent;
    StringValue* plistSHA256String;
    unsigned int plistHash[32];
    int i;
    
    *bundlePath = NULL;
    
    inputIPSWFile = fopen(inputIPSW, "rb");
    if(!inputIPSWFile) {
        return NULL;
    }
    
    XLOG(0, "Hashing IPSW...\n");
    
    buffer = malloc(BUFFERSIZE);
    SHA256_Init(&sha_ctx);
    while(!feof(inputIPSWFile)) {
        read = fread(buffer, 1, BUFFERSIZE, inputIPSWFile);
        SHA256_Update(&sha_ctx, buffer, read);
    }
    SHA256_Final(hash, &sha_ctx);
    free(buffer);
    
    fclose(inputIPSWFile);
    
    XLOG(0, "Matching IPSW in %s... (%02x%02x%02x%02x...)\n", bundleRoot, (int) hash[0], (int) hash[1], (int) hash[2], (int) hash[3]);
    
    dir = opendir(bundleRoot);
    if(dir == NULL) {
        XLOG(1, "Bundles directory not found\n");
        return NULL;
    }
    
    while((ent = readdir(dir)) != NULL) {
        if(ent->d_name[0] == '.' && (ent->d_name[1] == '\0' || (ent->d_name[1] == '.' && ent->d_name[2] == '\0'))) {
            continue;
        }
        
        infoPath = (char*) malloc(sizeof(char) * (strlen(bundleRoot) + sizeof(PATH_SEPARATOR) + strlen(ent->d_name) + sizeof(PATH_SEPARATOR "Info.plist")));
        sprintf(infoPath, "%s" PATH_SEPARATOR "%s" PATH_SEPARATOR "Info.plist", bundleRoot, ent->d_name);
        XLOG(0, "checking: %s\n", infoPath);
        
        if((plistFile = createAbstractFileFromFile(fopen(infoPath, "rb"))) != NULL) {
            plist = (char*) malloc(plistFile->getLength(plistFile));
            plistFile->read(plistFile, plist, plistFile->getLength(plistFile));
            plistFile->close(plistFile);
            info = createRoot(plist);
            free(plist);
            
            plistSHA256String = (StringValue*)getValueByKey(info, "SHA256");
            if(plistSHA256String) {
                sscanf(plistSHA256String->value, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                       &plistHash[0], &plistHash[1], &plistHash[2], &plistHash[3], &plistHash[4],
                       &plistHash[5], &plistHash[6], &plistHash[7], &plistHash[8], &plistHash[9],
                       &plistHash[10], &plistHash[11], &plistHash[12], &plistHash[13], &plistHash[14],
                       &plistHash[15], &plistHash[16], &plistHash[17], &plistHash[18], &plistHash[19],
                       &plistHash[20], &plistHash[21], &plistHash[22], &plistHash[23], &plistHash[24],
                       &plistHash[25], &plistHash[26], &plistHash[27], &plistHash[28], &plistHash[29],
                       &plistHash[30], &plistHash[31]);
                
                for(i = 0; i < 32; i++) {
                    if(plistHash[i] != hash[i]) {
                        break;
                    }
                }
                
                if(i == 32) {
                    *bundlePath = (char*) malloc(sizeof(char) * (strlen(bundleRoot) + sizeof(PATH_SEPARATOR) + strlen(ent->d_name)));
                    sprintf(*bundlePath, "%s" PATH_SEPARATOR "%s", bundleRoot, ent->d_name);
                    
                    free(infoPath);
                    break;
                }
            }
            
            releaseDictionary(info);
        }
        
        free(infoPath);
    }
    
    closedir(dir);
    
    if(*bundlePath == NULL) {
        return NULL;
    }
    
    *state = loadZip3(inputIPSW, useMemory);
    
    return info;
}

int doPatch(StringValue* patchValue, StringValue* fileValue, const char* bundlePath, OutputState** state, unsigned int* key, unsigned int* iv, int useMemory, int isPlain) {
    char* patchPath;
    size_t bufferSize;
    void* buffer;
    
    AbstractFile* patchFile;
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
    
    patchPath = malloc(sizeof(char) * (strlen(bundlePath) + strlen(patchValue->value) + 2));
    strcpy(patchPath, bundlePath);
    strcat(patchPath, "/");
    strcat(patchPath, patchValue->value);
    
    XLOG(0, "%s (%s)... ", fileValue->value, patchPath); fflush(stdout);
    
    patchFile = createAbstractFileFromFile(fopen(patchPath, "rb"));
    
    if (isPlain) {
        out = outRaw;
        file = getFileFromOutputState(state, fileValue->value);
    } else {
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
    
    if(!patchFile || !file || !out) {
        XLOG(0, "file error\n");
        exit(0);
    }
    
    if(patch(file, out, patchFile) != 0) {
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
    
    free(patchPath);
    
    return 0;
}

int doDecrypt(StringValue* decryptValue, StringValue* fileValue, const char* bundlePath, OutputState** state, unsigned int* key, unsigned int* iv, int useMemory) {
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
    
    out = duplicateAbstractFile(getFileFromOutputState(state, fileValue->value), outRaw);
    file = openAbstractFile3(getFileFromOutputState(state, fileValue->value), key, iv, 0);
    
    if(!file || !out) {
        XLOG(0, "file error\n");
        exit(0);
    }
    
    char *buf = malloc(1024 * 1024);
    off_t inDataSize = file->getLength(file);
    while (inDataSize > 0) {
        off_t avail, chunk = 1024 * 1024;
        if (chunk > inDataSize) {
            chunk = inDataSize;
        }
        if (chunk < 0) {
            XLOG(0, "decrypt failed\n");
            exit(0);
        }
        avail = file->read(file, buf, chunk);
        out->write(out, buf, avail);
        if (avail < chunk) {
            break;
        }
        inDataSize -= chunk;
    }
    out->close(out);
    file->close(file);
    free(buf);
    
    XLOG(0, "writing... "); fflush(stdout);
    
    if (decryptValue) {
        fileValue = decryptValue;
    }
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

void doPatchInPlace(Volume* volume, const char* filePath, const char* patchPath) {
    void* buffer;
    void* buffer2;
    size_t bufferSize;
    size_t bufferSize2;
    AbstractFile* bufferFile;
    AbstractFile* patchFile;
    AbstractFile* out;
    
    
    buffer = malloc(1);
    bufferSize = 0;
    bufferFile = createAbstractFileFromMemoryFile((void**)&buffer, &bufferSize);
    
    XLOG(0, "retrieving..."); fflush(stdout);
    get_hfs(volume, filePath, bufferFile);
    bufferFile->close(bufferFile);
    
    XLOG(0, "patching..."); fflush(stdout);
    
    patchFile = createAbstractFileFromFile(fopen(patchPath, "rb"));
    
    buffer2 = malloc(1);
    bufferSize2 = 0;
    out = duplicateAbstractFile(createAbstractFileFromMemoryFile((void**)&buffer, &bufferSize), createAbstractFileFromMemoryFile((void**)&buffer2, &bufferSize2));
    
    // reopen the inner package
    bufferFile = openAbstractFile(createAbstractFileFromMemoryFile((void**)&buffer, &bufferSize));
    
    if(!patchFile || !bufferFile || !out) {
        XLOG(0, "file error\n");
        exit(0);
    }
    
    if(patch(bufferFile, out, patchFile) != 0) {
        XLOG(0, "patch failed\n");
        exit(0);
    }
    
    XLOG(0, "writing... "); fflush(stdout);
    add_hfs(volume, createAbstractFileFromMemoryFile((void**)&buffer2, &bufferSize2), filePath);
    free(buffer2);
    free(buffer);
    
    XLOG(0, "success\n"); fflush(stdout);
}

void doPatchInPlaceMemoryPatch(Volume* volume, const char* filePath, void** patchData, size_t* patchSize) {
    void* buffer;
    void* buffer2;
    size_t bufferSize;
    size_t bufferSize2;
    AbstractFile* bufferFile;
    AbstractFile* patchFile;
    AbstractFile* out;
    
    buffer = malloc(1);
    bufferSize = 0;
    bufferFile = createAbstractFileFromMemoryFile((void**)&buffer, &bufferSize);
    
    XLOG(0, "retrieving..."); fflush(stdout);
    get_hfs(volume, filePath, bufferFile);
    bufferFile->close(bufferFile);
    
    XLOG(0, "patching..."); fflush(stdout);
    
    patchFile = createAbstractFileFromMemoryFile(patchData, patchSize);
    
    buffer2 = malloc(1);
    bufferSize2 = 0;
    out = duplicateAbstractFile(createAbstractFileFromMemoryFile((void**)&buffer, &bufferSize), createAbstractFileFromMemoryFile((void**)&buffer2, &bufferSize2));
    
    // reopen the inner package
    bufferFile = openAbstractFile(createAbstractFileFromMemoryFile((void**)&buffer, &bufferSize));
    
    if(!patchFile || !bufferFile || !out) {
        XLOG(0, "file error\n");
        exit(0);
    }
    
    if(patch(bufferFile, out, patchFile) != 0) {
        XLOG(0, "patch failed\n");
        exit(0);
    }
    
    XLOG(0, "writing... "); fflush(stdout);
    add_hfs(volume, createAbstractFileFromMemoryFile((void**)&buffer2, &bufferSize2), filePath);
    free(buffer2);
    free(buffer);
    
    XLOG(0, "success\n"); fflush(stdout);
}

void createRestoreOptions(Volume* volume, const char *optionsPlist, int SystemPartitionSize, int UpdateBaseband) {
    AbstractFile* plistFile;
    Dictionary* info;
    char* plist;
    
    HFSPlusCatalogRecord* record;
    info = NULL;
    record = getRecordFromPath(optionsPlist, volume, NULL, NULL);
    if(record != NULL && record->recordType == kHFSPlusFileRecord) {
        HFSPlusCatalogFile* file = (HFSPlusCatalogFile*)record;
        size_t bufferSize = 512;
        plist = malloc(bufferSize);
        plistFile = createAbstractFileFromMemory((void**)&plist, bufferSize);
        if (plistFile) {
            char zero = 0;
            writeToFile(file, plistFile, volume);
            plistFile->write(plistFile, &zero, sizeof(zero));
            plistFile->close(plistFile);
            info = createRoot(plist);
            removeKey(info, "CreateFilesystemPartitions");
            removeKey(info, "SystemPartitionSize");
            removeKey(info, "UpdateBaseband");
            removeKey(info, "MinimumSystemPartition");
            addIntegerToDictionary(info, "MinimumSystemPartition", SystemPartitionSize);
            XLOG(0, "got %s from ramdisk\n", optionsPlist);
        }
        free(plist);
    }
    
    XLOG(0, "start create restore options\n");
    
    if (!info) info = createRoot("<dict></dict>");
    addBoolToDictionary(info, "CreateFilesystemPartitions", TRUE);
    addIntegerToDictionary(info, "SystemPartitionSize", SystemPartitionSize);
    addBoolToDictionary(info, "UpdateBaseband", UpdateBaseband);
    
    plist = getXmlFromRoot(info);
    releaseDictionary(info);
    
    XLOG(0, "%s", plist);
    
    plistFile = createAbstractFileFromMemory((void**)&plist, sizeof(char) * strlen(plist));
    
    add_hfs(volume, plistFile, optionsPlist);
    free(plist);
}

int mergeIdentities(Dictionary* manifest, AbstractFile *idFile) {
    char *disk = NULL;
    Dictionary *dict;
    StringValue *path;
    StringValue *mainBuildVersion, *buildVersion;
    
    mainBuildVersion = (StringValue *)getValueByKey(manifest, "ProductBuildVersion");
    if (!mainBuildVersion) {
        return -1;
    }
    
    ArrayValue *buildIdentities = (ArrayValue *)getValueByKey(manifest, "BuildIdentities");
    if (buildIdentities && buildIdentities->size) {
        dict = (Dictionary *)buildIdentities->values[0];
        if (!dict) return -1;
        dict = (Dictionary *)getValueByKey(dict, "Manifest");
        if (!dict) return -1;
        dict = (Dictionary *)getValueByKey(dict, "RestoreRamDisk");
        if (!dict) return -1;
        dict = (Dictionary *)getValueByKey(dict, "Info");
        if (!dict) return -1;
        path = (StringValue *)getValueByKey(dict, "Path");
        if (!path) return -1;
        disk = strdup(path->value);
    }
    if (!disk) {
        return -1;
    }
    
    Dictionary* id = NULL;
    size_t fileLength = idFile->getLength(idFile);
    char *plist = malloc(fileLength);
    idFile->read(idFile, plist, fileLength);
    id = createRoot(plist);
    free(plist);
    
    buildVersion = (StringValue *)getValueByKey(manifest, "ProductBuildVersion");
    if (!buildVersion || strcmp(mainBuildVersion->value, buildVersion->value)) {
        return -1;
    }
    
    ArrayValue *newIdentities = (ArrayValue *)getValueByKey(id, "BuildIdentities");
    if (newIdentities && newIdentities->size) {
        dict = (Dictionary *)newIdentities->values[0];
        if (!dict) return -1;
        dict = (Dictionary *)getValueByKey(dict, "Manifest");
        if (!dict) return -1;
        dict = (Dictionary *)getValueByKey(dict, "RestoreRamDisk");
        if (!dict) return -1;
        dict = (Dictionary *)getValueByKey(dict, "Info");
        if (!dict) return -1;
        path = (StringValue *)getValueByKey(dict, "Path");
        if (!path) return -1;
        free(path->value);
        path->value = disk;
        prependToArray(buildIdentities, newIdentities->values[0]);
        unlinkValueFromDictionary(id, (DictValue *)newIdentities);
        releaseDictionary(id);
        releaseArrayEx(newIdentities, 0);
        return 0;
    }
    
    return -1;
}
