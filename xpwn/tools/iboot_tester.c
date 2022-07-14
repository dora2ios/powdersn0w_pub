#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include <mach-o/loader.h>

#include <abstractfile.h>
#include <patchfinder.h>
#include <xpwn/nor_files.h>
#include <iboot/iboot.h>

#define LOG(x, ...)               do { printf("\x1b[32m"x"\x1b[39m\n", ##__VA_ARGS__); } while(0)

unsigned int key[] = {
    0x45, 0x99, 0x12, 0xdd, 0xee, 0xeb, 0x9d, 0x4a,
    0x1c, 0x66, 0x06, 0x8c, 0x8c, 0x1d, 0x8f, 0x46,
    0xd8, 0xdd, 0x72, 0xe3, 0xe7, 0xdf, 0xa3, 0xff,
    0x03, 0x26, 0xf1, 0xab, 0x6b, 0xb5, 0x9c, 0x28
};

unsigned int iv[] = {
    0x1d, 0x45, 0xb6, 0xca, 0x42, 0xda, 0xfd, 0x5d,
    0x71, 0x1e, 0x3d, 0x23, 0xe5, 0xfa, 0x0f, 0xc7
};

int main(int argc, char **argv)
{
    init_libxpwn(&argc, argv);
    if(argc != 2) {
        LOG("[%s] %s <in.img3>", __FUNCTION__, argv[0]);
        return 0;
    }
    
    unsigned char* outBuf = NULL;
    size_t outSize = 0;
    
    AbstractFile* inFile = createAbstractFileFromFile(fopen(argv[1], "rb"));
    AbstractFile* tmpFile = createAbstractFileFromFile(fopen(argv[1], "rb"));
    
    patchiBootFromAbstractFile(inFile, tmpFile, &outBuf, &outSize, iv, key);
    
    LOG("[%s] %x", __FUNCTION__, *(uint32_t*)outBuf);
    return 0;
}
