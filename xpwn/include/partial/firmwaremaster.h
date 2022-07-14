#ifndef FIRMWAREMASTER_H
#define FIRMWAREMASTER_H

const char* FirmwareGetHardwareID(const char* platform);
char* FirmwareGetURL(const char* platform, const char* version);

#endif
