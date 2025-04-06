#ifndef FALSIFYPACKETS_H
#define FALSIFYPACKETS_H
#include <stdint.h>
char IsIPPacket(char *SrcStr, uint32_t Len);
char IsARPPacket(char *SrcStr, uint32_t Len);
char IsDNSPacket(char *SrcStr, uint32_t Len);
char *FalsifyResponseARP(char *SrcStr, char *DestStr, char *MyMac, char *MyIP);
char *FalsifyResponseDNS(const char *StrFromClient, const char *StrFromServer,
                         uint32_t LenOfServerRes, char *DestStr, const char *MyIP);
#endif
