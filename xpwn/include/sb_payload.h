#ifndef SB_PAYLOAD_H
#define SB_PAYLOAD_H

unsigned char sbPayload6[] = {
    0x03, 0xb4, 0x78, 0x46, 0x00, 0xf1, 0x05, 0x00, 0x00, 0x47, 0x03, 0xbc,
    0x1f, 0xb5, 0x91, 0xb0, 0x5c, 0x69, 0x00, 0x2c, 0x26, 0xd0, 0x69, 0x46,
    0x40, 0x20, 0x10, 0xaa, 0x10, 0x60, 0x20, 0x46, 0x41, 0x41, 0x41, 0x41,
    0x1c, 0x28, 0x01, 0xd0, 0x00, 0x28, 0x1b, 0xd1, 0x68, 0x46, 0x12, 0xa1,
    0x13, 0x22, 0x42, 0x42, 0x42, 0x42, 0x00, 0x28, 0x0d, 0xd1, 0x68, 0x46,
    0x13, 0xa1, 0x31, 0x22, 0x42, 0x42, 0x42, 0x42, 0x00, 0x28, 0x0d, 0xd0,
    0x68, 0x46, 0x1d, 0xa1, 0x27, 0x22, 0x42, 0x42, 0x42, 0x42, 0x00, 0x28,
    0x06, 0xd1, 0x11, 0xb0, 0x01, 0xbc, 0x00, 0x21, 0x01, 0x60, 0x18, 0x21,
    0x41, 0x60, 0x1e, 0xbd, 0x11, 0xb0, 0x05, 0x98, 0x86, 0x46, 0x1f, 0xbc,
    0x01, 0xb0, 0xff, 0xe7, 0x43, 0x43, 0x43, 0x43, 0x44, 0x44, 0x44, 0x44,
    0x2f, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x72,
    0x2f, 0x6d, 0x6f, 0x62, 0x69, 0x6c, 0x65, 0x00, 0x2f, 0x70, 0x72, 0x69,
    0x76, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x72, 0x2f, 0x6d, 0x6f, 0x62,
    0x69, 0x6c, 0x65, 0x2f, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2f,
    0x50, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x73, 0x2f,
    0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x00, 0xc0, 0x46,
    0x2f, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x72,
    0x2f, 0x6d, 0x6f, 0x62, 0x69, 0x6c, 0x65, 0x2f, 0x4c, 0x69, 0x62, 0x72,
    0x61, 0x72, 0x79, 0x2f, 0x50, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e,
    0x63, 0x65, 0x73, 0x00
};
size_t sbPayloadLen6 = 232;

#define VN_GETPATH_BL_OFFSET6   (0x20)
#define MEMCMP_BL_1_OFFSET6     (0x32)
#define MEMCMP_BL_2_OFFSET6     (0x40)
#define MEMCMP_BL_3_OFFSET6     (0x4e)

#define RESTORE_OFFSET6         (0x70)
#define JUMPBACK_OFFSET6        (0x74)

// taig
unsigned char sbPayload[] = {
    0x1f, 0xb5, 0x06, 0x9b, 0xad, 0xf5, 0x82, 0x6d, 0x1c, 0x6b, 0x01, 0x2c,
    0x32, 0xd1, 0x5c, 0x6b, 0x00, 0x2c, 0x2f, 0xd0, 0x69, 0x46, 0x5f, 0xf4,
    0x80, 0x60, 0x0d, 0xf5, 0x80, 0x62, 0x10, 0x60, 0x20, 0x46, 0x41, 0x41,
    0x41, 0x41, 0x1c, 0x28, 0x08, 0xd0, 0x00, 0x28, 0x22, 0xd1, 0x68, 0x46,
    0x15, 0xa1, 0x10, 0x22, 0x42, 0x42, 0x42, 0x42, 0x00, 0x28, 0x1b, 0xd0,
    0x68, 0x46, 0x0f, 0xf2, 0x59, 0x01, 0x13, 0x22, 0x42, 0x42, 0x42, 0x42,
    0x00, 0x28, 0x0b, 0xd1, 0x68, 0x46, 0x31, 0x22, 0x42, 0x42, 0x42, 0x42,
    0x00, 0x28, 0x0d, 0xd0, 0x68, 0x46, 0x27, 0x22, 0x42, 0x42, 0x42, 0x42,
    0x00, 0x28, 0x07, 0xd1, 0x0d, 0xf5, 0x82, 0x6d, 0x01, 0xbc, 0x00, 0x21,
    0x01, 0x60, 0x18, 0x21, 0x01, 0x71, 0x1e, 0xbd, 0x0d, 0xf5, 0x82, 0x6d,
    0x05, 0x98, 0x86, 0x46, 0x1f, 0xbc, 0x01, 0xb0, 0x43, 0x43, 0x43, 0x43,
    0x44, 0x44, 0x44, 0x44, 0x2f, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65,
    0x2f, 0x76, 0x61, 0x72, 0x2f, 0x74, 0x6d, 0x70, 0x00, 0x2f, 0x70, 0x72,
    0x69, 0x76, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x72, 0x2f, 0x6d, 0x6f,
    0x62, 0x69, 0x6c, 0x65, 0x2f, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79,
    0x2f, 0x50, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x73,
    0x2f, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x00, 0x00
};

size_t sbPayloadLen = 204;

#define VN_GETPATH_BL_OFFSET    (0x22)
#define MEMCMP_BL_1_OFFSET      (0x34)
#define MEMCMP_BL_2_OFFSET      (0x44)
#define MEMCMP_BL_3_OFFSET      (0x50)
#define MEMCMP_BL_4_OFFSET      (0x5c)

#define RESTORE_OFFSET          (0x80)
#define JUMPBACK_OFFSET         (0x84)

#endif
