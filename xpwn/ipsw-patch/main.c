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

#include <fstab.h>
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
    char* bundleRoot = "FirmwareBundles/";
    
    int mergePaths;
    char* outputIPSW;
    
    char updateBB = FALSE;
    char useMemory = FALSE;
    
    unsigned int key[32];
    unsigned int iv[16];
    
    unsigned int* pKey = NULL;
    unsigned int* pIV = NULL;
    
    Dictionary* configInfo = NULL;
    const char* configPlist = "FirmwareBundles/config.plist";
    char needPref = FALSE;
    char jailbreak = FALSE;
    char debugMode = FALSE;
    char useCustomBootArgs = FALSE;
    char* extraBootArgs = NULL;
    
    Dictionary* baseInfo = NULL;
    char useBaseFW = FALSE;
    char* baseIPSW = NULL;
    char* baseBundlePath = NULL;
    OutputState* baseOutputState = NULL;
    Dictionary* baseFWPath = NULL;
    Dictionary* baseFWDict = NULL;
    Dictionary* baseFWInject = NULL;
    Dictionary* baseInjectDict = NULL;
    
    char hasFWBootstrap = FALSE;
    char hasFWPackage = FALSE;
    char hasRDPackage = FALSE;
    size_t rdsize = 0;
    
    size_t fwBootstrapSize = 0;
    size_t fwPackageSize = 0;
    size_t rdPackageSize = 0;
    
    const char* bootstrapPath = NULL;
    const char* fwPackagePath = NULL;
    const char* rdPackagePath = NULL;
    const char* selectVersion = NULL;
    
    AbstractFile *ticketFile = NULL;
    Dictionary* shsh = NULL;
    
    if(argc < 3) {
        XLOG(0, "usage %s <input.ipsw> <target.ipsw> [-memory] [-bbupdate] [-base <base.ipsw>] [-apticket <ticket.der>] <package1.tar> <package2.tar>...\n", argv[0]);
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
        if(strcmp(argv[i], "-bbupdate") == 0) {
            updateBB = TRUE;
            continue;
        }
        if(strcmp(argv[i], "-base") == 0) {
            useBaseFW = TRUE;
            baseIPSW = argv[i + 1];
            i++;
            continue;
        }
        if(strcmp(argv[i], "-apticket") == 0) {
            ticketFile = createAbstractFileFromFile(fopen(argv[i + 1], "rb"));
            if(!ticketFile) {
                XLOG(0, "cannot open %s\n", argv[i + 1]);
                exit(1);
            }
            i++;
            continue;
        }
    }
    
    mergePaths = i;
    
    info = parseIPSW2(argv[1], bundleRoot, &bundlePath, &outputState, useMemory);
    if(info == NULL) {
        XLOG(0, "error: Could not load IPSW\n");
        exit(1);
    }
    
    if(useBaseFW) {
        baseInfo = parseIPSW3(baseIPSW, bundleRoot, &baseBundlePath, &baseOutputState, useMemory);
        if(baseInfo == NULL) {
            XLOG(0, "error: Could not load baseIPSW\n");
            exit(1);
        }
    }
    
    configInfo = openDict(configPlist);
    if(configInfo == NULL) {
        XLOG(0, "error: Could not config.plist\n");
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
    
    // set config
    Dictionary* iBootPatches = (Dictionary*)getValueByKey(configInfo, "iBootPatches");
    if(iBootPatches) {
        BoolValue* bootArgsInjection = (BoolValue*)getValueByKey(iBootPatches, "bootArgsInjection");
        StringValue* bootArgsString = (StringValue*)getValueByKey(iBootPatches, "bootArgsString");
        BoolValue* hasDebug = (BoolValue*)getValueByKey(iBootPatches, "debugEnabled");
        if(bootArgsInjection && bootArgsString) {
            useCustomBootArgs = bootArgsInjection->value;
            extraBootArgs = bootArgsString->value;
        }
        if(hasDebug) {
            debugMode = hasDebug->value;
            XLOG(0, "[+] debugMode ? %d...\n", debugMode);
        }
    }
    
    BoolValue* isNeedPref = (BoolValue*)getValueByKey(configInfo, "needPref");
    if(isNeedPref){
            needPref = isNeedPref->value;
            XLOG(0, "[+] needPref ? %d...\n", needPref);
    }
    
    BoolValue* isJailbreak = (BoolValue*)getValueByKey(configInfo, "FilesystemJailbreak");
    if(isJailbreak){
        jailbreak = isJailbreak->value;
        XLOG(0, "[+] jailbreak ? %d...\n", jailbreak);
    }
    
    if(jailbreak) {
        debugMode = TRUE;
        XLOG(0, "[+] debugMode ? %d...\n", debugMode);
    }
    
    {
        char str[MAX_BOOTARGS_LEN];
        memset(&str, 0x0, MAX_BOOTARGS_LEN);
        
        if(jailbreak) {
            if(strlen(CSBYPASS_BOOTARGS) + 1 > MAX_BOOTARGS_LEN) {
                XLOG(0, "error: CSBYPASS_BOOTARGS is too large!\n");
                exit(1);
            }
            sprintf(str, "%s", CSBYPASS_BOOTARGS);
        }
        
        if(useCustomBootArgs) {
            if(strlen(str) + strlen(extraBootArgs) + 1 > MAX_BOOTARGS_LEN) {
                XLOG(0, "error: extraBootArgs is too large!\n");
                exit(1);
            }
            if(jailbreak)
                sprintf(str, "%s %s", str, extraBootArgs);
            else
                sprintf(str, "%s", extraBootArgs);
        }
        
        if(jailbreak || useCustomBootArgs)
            bootargs = str;
        else
            bootargs = NULL;
        
        if(bootargs)
            XLOG(0, "[*] bootArgs: %s\n", bootargs);
    }
    
    if(useBaseFW) {
        // injecting base .img3 imaegs
        
        StringValue* baseFileValue = NULL;
        StringValue* baseManifestValue = NULL;
        StringValue* ibobKeyValue = NULL;
        StringValue* ibobIvValue = NULL;
        
        const char* scabPath = NULL;
        const char* logoPath = NULL;
        const char* logbPath = NULL;
        const char* recmPath = NULL;
        const char* recbPath = NULL;
        const char* illbPath = NULL;
        const char* ibotPath = NULL;
        const char* ibobPath = NULL;
        
        const char* BatteryCharging0Path = NULL;
        const char* BatteryCharging1Path = NULL;
        const char* BatteryFullPath = NULL;
        const char* BatteryLow0Path = NULL;
        const char* BatteryLow1Path = NULL;
        const char* BatteryPluginPath = NULL;
        
        StringValue* ibobValue = NULL;
        const char* ibobKey = NULL;
        const char* ibobIv = NULL;
        
        const char* manifestPath = NULL;
        const char* manifestFileValue = NULL;
        
        size_t fileLength = 0;
        
        unsigned int* decKey = NULL;
        unsigned int* decIv = NULL;
        
        baseFWPath = (Dictionary*)getValueByKey(baseInfo, "FirmwarePath");
        if(baseFWPath == NULL) {
            XLOG(0, "error: Could not load baseIPSW info\n");
            exit(1);
        }
        
        baseFWDict = (Dictionary*) baseFWPath->values;
        if(baseFWDict == NULL) {
            XLOG(0, "error: Could not load baseIPSW info\n");
            exit(1);
        }
        
        baseFWInject = (Dictionary*)getValueByKey(info, "FirmwareReplace");
        if(baseFWInject == NULL) {
            XLOG(0, "error: Could not load IPSW info\n");
            exit(1);
        }
        
        baseInjectDict = (Dictionary*) baseFWInject->values;
        if(baseInjectDict == NULL) {
            XLOG(0, "error: Could not load IPSW info\n");
            exit(1);
        }
        
        while(baseInjectDict != NULL) {
            baseFileValue = (StringValue*) getValueByKey(baseInjectDict, "File");
            baseManifestValue = (StringValue*) getValueByKey(baseInjectDict, "manifest");
            
            if(strcmp(baseInjectDict->dValue.key, "APTicket") == 0) {
                // buggy
                char* plist;
                
                scabPath = baseFileValue->value;
                if(scabPath == NULL) {
                    XLOG(0, "error: Could not found APTicket\n");
                    exit(1);
                }
                
                XLOG(0, "[*] Found APTicket: %s\n", scabPath);
                
                plist = (char*) malloc(ticketFile->getLength(ticketFile));
                ticketFile->read(ticketFile, plist, ticketFile->getLength(ticketFile));
                ticketFile->close(ticketFile);
                shsh = createRoot(plist);
                free(plist);
                
                DataValue* ticketValue = (DataValue*) getValueByKey(shsh, "APTicket");
                if(ticketValue) {
                    AbstractFile* ticketInput = NULL;
                    AbstractFile* ticketTemplate = NULL;
                    AbstractFile* apticketInput = NULL;
                    AbstractFile* ticketOutput = NULL;
                    AbstractFile* newTicket = NULL;
                    
                    void* ticketBuf = NULL;
                    void* scabBuf = NULL;
                    void* apBuf = NULL;
                    void* inData = NULL;
                    size_t ticketSize = 0;
                    size_t scabSize = 0;
                    size_t apSize = 0;
                    size_t inDataSize = 0;
                    
                    ticketSize = ticketValue->len;
                    ticketBuf = malloc(ticketSize);
                    memcpy(ticketBuf, ticketValue->value, ticketSize);
                    
                    scabSize = scab_template_len;
                    scabBuf = malloc(scabSize);
                    memcpy(scabBuf, scab_template, scabSize);
                    
                    apSize = ticketSize;
                    apBuf = malloc(apSize);
                    memcpy(apBuf, ticketBuf, apSize);
                    
                    ticketInput = createAbstractFileFromMemoryFile((void**)&ticketBuf, &ticketSize);
                    ticketTemplate = createAbstractFileFromMemoryFile((void**)&scabBuf, &scabSize);
                    apticketInput = openAbstractFile(ticketInput);
                    
                    ticketOutput = createAbstractFileFromMemoryFile((void**)&apBuf, &apSize);
                    newTicket = duplicateAbstractFile2(ticketTemplate, ticketOutput, NULL, NULL, NULL);
                    
                    inDataSize = (size_t)apticketInput->getLength(apticketInput);
                    inData = malloc(inDataSize);
                    
                    apticketInput->read(apticketInput, inData, inDataSize);
                    apticketInput->close(apticketInput);
                    
                    newTicket->write(newTicket, inData, inDataSize);
                    newTicket->close(newTicket);
                    
                    addToOutput(&outputState, scabPath, apBuf, apSize);
                    XLOG(0, "[+] Added: %s\n", scabPath);
                } else {
                    XLOG(1, "cannot read apticket\n");
                    exit(1);
                }
            }
            
            if(strcmp(baseInjectDict->dValue.key, "AppleLogo") == 0) {
                logoPath = baseFileValue->value;
                XLOG(0, "[*] Found AppleLogo: %s\n", logoPath);
            }
            if(strcmp(baseInjectDict->dValue.key, "NewAppleLogo") == 0) {
                logbPath = baseFileValue->value;
                XLOG(0, "[*] Found NewAppleLogo: %s\n", logbPath);
            }
            if(strcmp(baseInjectDict->dValue.key, "RecoveryMode") == 0) {
                recmPath = baseFileValue->value;
                XLOG(0, "[*] Found RecoveryMode: %s\n", recmPath);
            }
            if(strcmp(baseInjectDict->dValue.key, "NewRecoveryMode") == 0) {
                recbPath = baseFileValue->value;
                XLOG(0, "[*] Found NewRecoveryMode: %s\n", recbPath);
            }
            if(strcmp(baseInjectDict->dValue.key, "BatteryCharging0") == 0) {
                BatteryCharging0Path = baseFileValue->value;
                XLOG(0, "[*] Found BatteryCharging0: %s\n", BatteryCharging0Path);
            }
            if(strcmp(baseInjectDict->dValue.key, "BatteryCharging1") == 0) {
                BatteryCharging1Path = baseFileValue->value;
                XLOG(0, "[*] Found BatteryCharging1: %s\n", BatteryCharging1Path);
            }
            if(strcmp(baseInjectDict->dValue.key, "BatteryFull") == 0) {
                BatteryFullPath = baseFileValue->value;
                XLOG(0, "[*] Found BatteryFull: %s\n", BatteryFullPath);
            }
            if(strcmp(baseInjectDict->dValue.key, "BatteryLow0") == 0) {
                BatteryLow0Path = baseFileValue->value;
                XLOG(0, "[*] Found BatteryLow0: %s\n", BatteryLow0Path);
            }
            if(strcmp(baseInjectDict->dValue.key, "BatteryLow1") == 0) {
                BatteryLow1Path = baseFileValue->value;
                XLOG(0, "[*] Found BatteryLow1: %s\n", BatteryLow1Path);
            }
            if(strcmp(baseInjectDict->dValue.key, "BatteryPlugin") == 0) {
                BatteryPluginPath = baseFileValue->value;
                XLOG(0, "[*] Found BatteryPlugin: %s\n", BatteryPluginPath);
            }
            if(strcmp(baseInjectDict->dValue.key, "LLB") == 0) {
                illbPath = baseFileValue->value;
                XLOG(0, "[*] Found LLB: %s\n", illbPath);
            }
            
            // iboot
            if(strcmp(baseInjectDict->dValue.key, "iBoot") == 0) {
                ibotPath = baseFileValue->value;
                XLOG(0, "[*] Found iBoot: %s\n", ibotPath);
            }
            if(strcmp(baseInjectDict->dValue.key, "NewiBoot") == 0) {
                ibobKeyValue = (StringValue*) getValueByKey(baseInjectDict, "Key");
                ibobIvValue = (StringValue*) getValueByKey(baseInjectDict, "IV");
                ibobValue = baseFileValue;
                if(ibobKeyValue)
                    ibobKey = ibobKeyValue->value;
                if(ibobIvValue)
                    ibobIv = ibobIvValue->value;
                
                ibobPath = baseFileValue->value;
                XLOG(0, "[*] Found NewiBoot: %s\n", ibobPath);
            }
            
            // manifest
            if(strcmp(baseInjectDict->dValue.key, "manifest") == 0) {
                char *manifestFilePath;
                char *newManifestFile;
                AbstractFile *newManifest;
                
                manifestPath = baseFileValue->value;
                if(manifestPath == NULL) {
                    XLOG(0, "error: Could not found manifest path\n");
                    exit(1);
                }
                manifestFileValue = baseManifestValue->value;
                if(manifestFileValue == NULL) {
                    XLOG(0, "error: Could not found manifest file value\n");
                    exit(1);
                }
                
                XLOG(0, "[*] Found manifestPath: %s\n", manifestPath);
                
                manifestFilePath = malloc(sizeof(char) * (strlen(bundlePath) + strlen(manifestFileValue) + 2));
                strcpy(manifestFilePath, bundlePath);
                strcat(manifestFilePath, "/");
                strcat(manifestFilePath, manifestFileValue);
                
                newManifest = createAbstractFileFromFile(fopen(manifestFilePath, "rb"));
                fileLength = newManifest->getLength(newManifest);
                newManifestFile = malloc(fileLength);
                newManifest->read(newManifest, newManifestFile, fileLength);
                newManifest->close(newManifest);
                
                addToOutput(&outputState, manifestPath, newManifestFile, fileLength);
                XLOG(0, "[+] Added: %s\n", manifestPath);
                
                free(manifestFilePath);
            }
            
            baseInjectDict = (Dictionary*) baseInjectDict->dValue.next;
        }
        
        StringValue* baseFWFileValue = NULL;
        
        while(baseFWDict != NULL) {
            XLOG(0, "[*] Replacing flash_nor...\n");
            baseFWFileValue = (StringValue*) getValueByKey(baseFWDict, "File");
            if(baseFWInject == NULL) {
                XLOG(0, "error: Could not found base firmware\n");
                exit(1);
            }
            if(baseFWFileValue->value == NULL) {
                XLOG(0, "error: Could not found base firmware value\n");
                exit(1);
            }
            
            if(strcmp(baseFWDict->dValue.key, "AppleLogo") == 0) {
                AbstractFile* file = NULL;
                char* buf = NULL;
                AbstractFile* newNORFile = NULL;
                char* newNORBuf = NULL;
                
                file = getFileFromOutputState(&baseOutputState, baseFWFileValue->value);
                fileLength = file->getLength(file);
                buf = malloc(fileLength);
                file->read(file, buf, fileLength);
                file->close(file);
                addToOutput(&outputState, logoPath, buf, fileLength);
                XLOG(0, "[+] Added: %s\n", logoPath);
                
                newNORFile = getFileFromOutputState(&outputState, logbPath);
                fileLength = newNORFile->getLength(newNORFile);
                newNORBuf = malloc(fileLength);
                newNORFile->read(newNORFile, newNORBuf, fileLength);
                
                XLOG(0, "[*] Rewrite img3 TYPE tag: %s -> %s\n", "logo", "logb");
                *(uint8_t*)(newNORBuf+0x10) = 0x62;
                *(uint8_t*)(newNORBuf+0x20) = 0x62;
                
                newNORFile->close(newNORFile);
                addToOutput(&outputState, logbPath, newNORBuf, fileLength);
                XLOG(0, "[+] Added: %s\n", logbPath);
            }
            if(strcmp(baseFWDict->dValue.key, "BatteryCharging0") == 0) {
                AbstractFile* file = NULL;
                char* buf = NULL;
                
                file = getFileFromOutputState(&baseOutputState, baseFWFileValue->value);
                fileLength = file->getLength(file);
                buf = malloc(fileLength);
                file->read(file, buf, fileLength);
                file->close(file);
                
                addToOutput(&outputState, BatteryCharging0Path, buf, fileLength);
                XLOG(0, "[+] Added: %s\n", BatteryCharging0Path);
            }
            if(strcmp(baseFWDict->dValue.key, "BatteryCharging1") == 0) {
                AbstractFile* file = NULL;
                char* buf = NULL;
                
                file = getFileFromOutputState(&baseOutputState, baseFWFileValue->value);
                fileLength = file->getLength(file);
                buf = malloc(fileLength);
                file->read(file, buf, fileLength);
                file->close(file);
                
                addToOutput(&outputState, BatteryCharging1Path, buf, fileLength);
                XLOG(0, "[+] Added: %s\n", BatteryCharging1Path);
            }
            if(strcmp(baseFWDict->dValue.key, "BatteryFull") == 0) {
                AbstractFile* file = NULL;
                char* buf = NULL;
                
                file = getFileFromOutputState(&baseOutputState, baseFWFileValue->value);
                fileLength = file->getLength(file);
                buf = malloc(fileLength);
                file->read(file, buf, fileLength);
                file->close(file);
                
                addToOutput(&outputState, BatteryFullPath, buf, fileLength);
                XLOG(0, "[+] Added: %s\n", BatteryFullPath);
            }
            if(strcmp(baseFWDict->dValue.key, "BatteryLow0") == 0) {
                AbstractFile* file = NULL;
                char* buf = NULL;
                
                file = getFileFromOutputState(&baseOutputState, baseFWFileValue->value);
                fileLength = file->getLength(file);
                buf = malloc(fileLength);
                file->read(file, buf, fileLength);
                file->close(file);
                
                addToOutput(&outputState, BatteryLow0Path, buf, fileLength);
                XLOG(0, "[+] Added: %s\n", BatteryLow0Path);
            }
            if(strcmp(baseFWDict->dValue.key, "BatteryLow1") == 0) {
                AbstractFile* file = NULL;
                char* buf = NULL;
                
                file = getFileFromOutputState(&baseOutputState, baseFWFileValue->value);
                fileLength = file->getLength(file);
                buf = malloc(fileLength);
                file->read(file, buf, fileLength);
                file->close(file);
                
                addToOutput(&outputState, BatteryLow1Path, buf, fileLength);
                XLOG(0, "[+] Added: %s\n", BatteryLow1Path);
            }
            if(strcmp(baseFWDict->dValue.key, "BatteryPlugin") == 0) {
                AbstractFile* file = NULL;
                char* buf = NULL;
                
                file = getFileFromOutputState(&baseOutputState, baseFWFileValue->value);
                fileLength = file->getLength(file);
                buf = malloc(fileLength);
                file->read(file, buf, fileLength);
                file->close(file);
                
                addToOutput(&outputState, BatteryPluginPath, buf, fileLength);
                XLOG(0, "[+] Added: %s\n", BatteryPluginPath);
            }
            if(strcmp(baseFWDict->dValue.key, "RecoveryMode") == 0) {
                AbstractFile* file = NULL;
                char* buf = NULL;
                AbstractFile* newNORFile = NULL;
                char* newNORBuf = NULL;
                
                file = getFileFromOutputState(&baseOutputState, baseFWFileValue->value);
                fileLength = file->getLength(file);
                buf = malloc(fileLength);
                file->read(file, buf, fileLength);
                file->close(file);
                addToOutput(&outputState, recmPath, buf, fileLength);
                XLOG(0, "[+] Added: %s\n", recmPath);
                
                newNORFile = getFileFromOutputState(&outputState, recbPath);
                fileLength = newNORFile->getLength(newNORFile);
                newNORBuf = malloc(fileLength);
                newNORFile->read(newNORFile, newNORBuf, fileLength);
                
                XLOG(0, "[*] Rewrite img3 TYPE tag: %s -> %s\n", "recm", "recb");
                *(uint8_t*)(newNORBuf+0x10) = 0x62;
                *(uint8_t*)(newNORBuf+0x20) = 0x62;
                
                newNORFile->close(newNORFile);
                addToOutput(&outputState, recbPath, newNORBuf, fileLength);
                XLOG(0, "[+] Added: %s\n", recbPath);
            }
            if(strcmp(baseFWDict->dValue.key, "LLB") == 0) {
                AbstractFile* file = NULL;
                char* buf = NULL;
                
                file = getFileFromOutputState(&baseOutputState, baseFWFileValue->value);
                fileLength = file->getLength(file);
                buf = malloc(fileLength);
                file->read(file, buf, fileLength);
                file->close(file);
                
                addToOutput(&outputState, illbPath, buf, fileLength);
                XLOG(0, "[+] Added: %s\n", illbPath);
            }
            
            // iboot
            if(strcmp(baseFWDict->dValue.key, "iBoot") == 0) {
                AbstractFile* file = NULL;
                char* buf = NULL;
                AbstractFile* newNORFile = NULL;
                char* newNORBuf = NULL;
                
                // patch
                XLOG(0, "[*] Creating new iBoot...\n");
                newNORFile = getFileFromOutputState(&outputState, ibotPath);
                fileLength = newNORFile->getLength(newNORFile);
                newNORBuf = malloc(fileLength);
                newNORFile->read(newNORFile, newNORBuf, fileLength);
                XLOG(0, "[*] Rewrite img3 TYPE tag: %s -> %s\n", "ibot", "ibob");
                *(uint8_t*)(newNORBuf+0x10) = 0x62;
                *(uint8_t*)(newNORBuf+0x20) = 0x62;
                newNORFile->close(newNORFile);
                addToOutput(&outputState, ibobPath, newNORBuf, fileLength);
                XLOG(0, "[+] Added: %s\n", ibobPath);
                
                XLOG(0, "[*] Patching iBoot...\n");
                decKey = NULL;
                decIv = NULL;
                if(ibobKey) {
                    sscanf(ibobKey, "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
                           &key[0], &key[1], &key[2], &key[3], &key[4], &key[5], &key[6], &key[7], &key[8],
                           &key[9], &key[10], &key[11], &key[12], &key[13], &key[14], &key[15],
                           &key[16], &key[17], &key[18], &key[19], &key[20], &key[21], &key[22], &key[23], &key[24],
                           &key[25], &key[26], &key[27], &key[28], &key[29], &key[30], &key[31]);
                    decKey = key;
                }
                if(ibobIv) {
                    sscanf(ibobIv, "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
                           &iv[0], &iv[1], &iv[2], &iv[3], &iv[4], &iv[5], &iv[6], &iv[7], &iv[8],
                           &iv[9], &iv[10], &iv[11], &iv[12], &iv[13], &iv[14], &iv[15]);
                    decIv = iv;
                }
                
                uint32_t debugFlags = PATCH_NONE;
                if(debugMode)
                    debugFlags |= PATCH_DEBUG;
                XLOG(0, "%s: ", baseFWDict->dValue.key); fflush(stdout);
                if(doiBootPatch(ibobValue, bundlePath, &outputState, decKey, decIv, useMemory, bootargs, debugFlags))  {
                    XLOG(0, "error: Could not patch iBoot\n");
                    exit(1);
                }
                XLOG(0, "%s: ", baseFWDict->dValue.key); fflush(stdout);
                doDecrypt(NULL, ibobValue, bundlePath, &outputState, decKey, decIv, useMemory);
                XLOG(0, "[*] Done: %s\n", ibobPath);
                
                // orig
                file = getFileFromOutputState(&baseOutputState, baseFWFileValue->value);
                fileLength = file->getLength(file);
                buf = malloc(fileLength);
                file->read(file, buf, fileLength);
                file->close(file);
                
                addToOutput(&outputState, ibotPath, buf, fileLength);
                XLOG(0, "[+] Added: %s\n", ibotPath);
                
            }
            
            baseFWDict = (Dictionary*) baseFWDict->dValue.next;
        }
        
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
                    
                    if(useCustomBootArgs) {
                        if(strlen(str) + strlen(extraBootArgs) + 1 > MAX_BOOTARGS_LEN) {
                            XLOG(0, "error: extraBootArgs is too large!\n");
                            exit(1);
                        }
                            sprintf(str, "%s %s", str, extraBootArgs);
                    }
                    
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
            
            BoolValue *decryptValue = (BoolValue *)getValueByKey(patchDict, "Decrypt");
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
            
            
            // 2, check jailbreak state
            if(jailbreak) {
                // 2-1, patch stock kc
                XLOG(0, "%s: ", patchDict->dValue.key); fflush(stdout);
                if(doKernelPatch(fileValue, bundlePath, &outputState, pKey, pIV, useMemory)) {
                    XLOG(0, "error: Could not patch Kernel\n");
                    exit(1);
                }
            }
            
            
            // 3, check Decrypt value
            if(decryptValue && decryptValue->value) {
                // 3-1, decrypt stock kc
                XLOG(0, "%s: ", patchDict->dValue.key); fflush(stdout);
                doDecrypt(NULL, fileValue, bundlePath, &outputState, pKey, pIV, useMemory);
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
    
    Dictionary* ramdiskPackage = (Dictionary*)getValueByKey(info, "RamdiskPackage");
    if(ramdiskPackage == NULL) {
        XLOG(0, "error: Could not load ramdisk packages\n");
        exit(1);
    }
    
    {
        StringValue* package = (StringValue*) getValueByKey(ramdiskPackage, "package");
        
        if(package) {
            rdPackagePath = package->value;
            AbstractFile* packageFile = createAbstractFileFromFile(fopen(rdPackagePath, "rb"));
            if(packageFile) {
                hasRDPackage = TRUE;
                rdPackageSize = packageFile->getLength(packageFile);
                rdsize += rdPackageSize;
                packageFile->close(packageFile);
                XLOG(0, "[*] Found: ramdisk package: %s\n", rdPackagePath);
            }
        }
        
        StringValue* selectValue = (StringValue*) getValueByKey(ramdiskPackage, "ios");
        if(selectValue) {
            selectVersion = selectValue->value;
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
    
    if(jailbreak)
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
    }
    
    if(needPref){
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
    
    if(rdsize) {
        rdsize += 1048576;
        size_t add = rdsize/(ramdiskVolume->volumeHeader->blockSize) + 64;
        ramdiskGrow += add;
    }
    
    XLOG(0, "growing ramdisk: %d -> %d\n", ramdiskVolume->volumeHeader->totalBlocks * ramdiskVolume->volumeHeader->blockSize, (ramdiskVolume->volumeHeader->totalBlocks + ramdiskGrow) * ramdiskVolume->volumeHeader->blockSize);
    grow_hfs(ramdiskVolume, (ramdiskVolume->volumeHeader->totalBlocks + ramdiskGrow) * ramdiskVolume->volumeHeader->blockSize);
    
    {
        // ASR patch
        doPatchASR(ramdiskVolume, "usr/sbin/asr");
    }
    
    if(hasRDPackage)
    {
        XLOG(0, "[*] Installing Package\n");
        AbstractFile* tarFile = NULL;
        
        XLOG(0, "merging %s\n", rdPackagePath);
        tarFile = createAbstractFileFromFile(fopen(rdPackagePath, "rb"));
        if(rdPackageSize != tarFile->getLength(tarFile)) {
            XLOG(1, "WTF!?\n");
            releaseOutput(&outputState);
            closeRoot(buffer);
            exit(0);
        }
        
        if(tarFile == NULL) {
            XLOG(1, "cannot find %s, make sure your slashes are in the right direction\n", rdPackagePath);
            releaseOutput(&outputState);
            closeRoot(buffer);
            exit(0);
        }
        if (tarFile->getLength(tarFile)) hfs_untar(ramdiskVolume, tarFile);
        tarFile->close(tarFile);
    }
    
    if(useBaseFW) {
        const char *rebootPath = "/sbin/reboot";
        const char *rerebootPath = "/sbin/reboot_";
        const char *exploit = "/exploit";
        
        
        Dictionary* exploitDict = (Dictionary*)getValueByKey(baseInfo, "RamdiskExploit");
        if(exploitDict == NULL) {
            XLOG(0, "error: Could not load exploit packages\n");
            exit(1);
        }
        
        StringValue* realExploit = (StringValue*) getValueByKey(exploitDict, "exploit");
        StringValue* injection = (StringValue*) getValueByKey(exploitDict, "inject");
        if(realExploit == NULL || injection == NULL) {
            XLOG(0, "error: Could not load exploit packages\n");
            exit(1);
        }
        
        const char *exploitPath = realExploit->value;
        const char *injectionPath = injection->value;
        
        if(exploitPath == NULL || injectionPath == NULL) {
            XLOG(0, "error: Could not load exploit packages\n");
            exit(1);
        }
        
        move(rebootPath, rerebootPath, ramdiskVolume);
        XLOG(0, "[+] ramdiskVolume ... Moved: %s -> %s\n", rebootPath, rerebootPath);
        
        AbstractFile* rebootBinFile = createAbstractFileFromFile(fopen(injectionPath, "rb"));
        if(rebootBinFile == NULL) {
            XLOG(1, "cannot find %s, make sure your slashes are in the right direction\n", injectionPath);
            releaseOutput(&outputState);
            closeRoot(buffer);
            exit(0);
        }
        if (rebootBinFile->getLength(rebootBinFile))
            add_hfs(ramdiskVolume, rebootBinFile, rebootPath);
        XLOG(0, "[+] ramdiskVolume ... Added: %s\n", rebootPath);
        
        AbstractFile* exploitFile = createAbstractFileFromFile(fopen(exploitPath, "rb"));
        if(exploitFile == NULL) {
            XLOG(1, "cannot find %s, make sure your slashes are in the right direction\n", exploitPath);
            releaseOutput(&outputState);
            closeRoot(buffer);
            exit(0);
        }
        if (exploitFile->getLength(exploitFile))
            add_hfs(ramdiskVolume, exploitFile, exploit);
        XLOG(0, "[+] ramdiskVolume ... Added: %s\n", exploit);
        
        XLOG(0, "[*] ramdiskVolume ... chmod: %s -rwx/-r-x/-r-x\n", rebootPath);
        chmodFile(rebootPath, 0755, ramdiskVolume);
        XLOG(0, "[*] ramdiskVolume ... chown: %s root:root\n", rebootPath);
        chownFile(rebootPath, 0, 0, ramdiskVolume);
    }
    
    if(selectVersion && jailbreak) {
        size_t dummy_sz = 1;
        void *dummy = malloc(dummy_sz);
        memset(dummy, 'A', dummy_sz);
        AbstractFile* dummyFile = createAbstractFileFromMemoryFile((void**)&dummy, &dummy_sz);
        add_hfs(ramdiskVolume, dummyFile, selectVersion);
        XLOG(0, "[+] ramdiskVolume ... Added dummyFile\n");
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
