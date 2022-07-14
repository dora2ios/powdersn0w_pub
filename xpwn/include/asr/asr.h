#ifndef ASR_H
#define ASR_H

#include <hfs/hfslib.h>

int patchASR(AbstractFile* inFile, AbstractFile* outFile);
void doPatchASR(Volume* volume, const char* filePath);

#endif
