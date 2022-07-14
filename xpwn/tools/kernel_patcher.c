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

#define LOG(x, ...)               do { printf("\x1b[32m"x"\x1b[39m\n", ##__VA_ARGS__); } while(0)

int main(int argc, char **argv)
{
    if(argc != 3) {
        LOG("[%s] %s <in_dec> <out_dec>", __FUNCTION__, argv[0]);
        return 0;
    }
    
    AbstractFile* inFile = createAbstractFileFromFile(fopen(argv[1], "rb"));
    AbstractFile* outFile = createAbstractFileFromFile(fopen(argv[2], "wb"));
    
    if(inFile && outFile)
        if(patchKernel(inFile, outFile))
            LOG("[%s] Failed!", __FUNCTION__);
    
    return 0;
}
