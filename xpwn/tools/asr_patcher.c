#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include <mach-o/loader.h>

#include <abstractfile.h>
#include <patchfinder.h>
#include <xpwn/nor_files.h>
#include <asr/asr.h>

#define LOG(x, ...)               do { printf("\x1b[32m"x"\x1b[39m\n", ##__VA_ARGS__); } while(0)

int main(int argc, char **argv)
{
    if(argc != 3) {
        LOG("[%s] %s <in> <out>", __FUNCTION__, argv[0]);
        return 0;
    }
    
    AbstractFile* inFile = createAbstractFileFromFile(fopen(argv[1], "rb"));
    AbstractFile* outFile = createAbstractFileFromFile(fopen(argv[2], "wb"));
    
    if(inFile && outFile)
        patchASR(inFile, outFile);
    
    return 0;
}
