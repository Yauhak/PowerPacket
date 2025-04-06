#ifndef PROTOCOLHEADERS_H
#define PROTOCOLHEADERS_H
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
typedef struct EtherHeader{
	uint8_t ErrMsg = 0;
	uint8_t DestMac[6];
	uint8_t SrcMac[6];
	uint16_t EtherType;
}EtherHeader; 
typedef struct IPv4Header{
	uint8_t ErrMsg = 0;
	uint8_t Ver;
	uint8_t HeadLen;
	uint16_t PackTotalLen;
	uint16_t Id;
	uint8_t Flags;
	uint16_t FragmentOffset;
	uint8_t TTL;
	uint8_t Protocol;
	uint8_t HeaderChecksum;
	uint8_t SrcAdd[4];
	uint8_t DestAdd[4];
}IPv4Header; 
typedef struct TCPHeader{
	uint8_t ErrMsg = 0;
	uint16_t SrcPort;
	uint16_t DestPort;
	uint32_t SeqNum;
	uint32_t ACKNum;
	uint8_t TCPHeadLen;
	uint8_t Reserved;
	uint8_t Flags;
	uint16_t Window;
	uint16_t Checksum;
	uint16_t UrgPtr;
}TCPHeader; 
typedef struct UDPHeader{
	uint8_t ErrMsg = 0;
	uint16_t SrcPort;
	uint16_t DestPort;
	uint16_t UDPHeadLen;
	uint16_t Checksum;
}UDPHeader; 
typedef struct IPv4ARPHeader{
	uint8_t ErrMsg = 0;
	uint16_t HardwareType;
	uint16_t ProtocolType;
	uint8_t HardwareAddLen;
	uint8_t ProtocolAddLen;
	uint16_t Operation;
	uint8_t SrcHardwareAdd[6];
	uint8_t SrcProtocolAdd[4];
	uint8_t TagHardwareAdd[6];
	uint8_t TagProtocolAdd[4];
}IPv4ARPHeader; 
EtherHeader EtherParser(char *Buffer,uint32_t Len);
IPv4Header IPv4Parser(char *Buffer,uint32_t Len);
TCPHeader TCPParser(char *Buffer,uint32_t Len);
UDPHeader UDPParser(char *Buffer,uint32_t Len);
IPv4ARPHeader IPv4ARPParser(char *Buffer,uint32_t Len);
uint16_t ToUint16(char *FirstAddr);
uint32_t ToUint32(char *FirstAddr);
uint16_t Checksum(char *Buffer,size_t Len);
#endif
