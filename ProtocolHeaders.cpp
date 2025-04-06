#include "ProtocolHeaders.h"
uint16_t ToUint16(char *FirstAddr) {
	return ((uint16_t)(*FirstAddr) << 8) | (uint16_t)(*(FirstAddr + 1));
}

uint32_t ToUint32(char *FirstAddr) {
	return ((uint32_t)ToUint16(FirstAddr) << 16) | ToUint16(FirstAddr + 2);
}

EtherHeader EtherParser(char *Buffer, uint32_t Len) {
	EtherHeader ParseList;
	if (Len < 14) {
		ParseList.ErrMsg = 1;
		return ParseList;
	}
	for (int i = 0; i < 6; i++) {
		ParseList.DestMac[i] = Buffer[i];
	}
	for (int i = 0; i < 6; i++) {
		ParseList.SrcMac[i] = Buffer[6 + i];
	}
	ParseList.EtherType = ToUint16(&Buffer[12]);
	return ParseList;
}

IPv4Header IPv4Parser(char *Buffer, uint32_t Len) {
	IPv4Header ParseList;
	if (Len < 20) {
		ParseList.ErrMsg = 1;
		return ParseList;
	}
	ParseList.Ver = Buffer[0] >> 4;
	ParseList.HeadLen = ((Buffer[0] & 0x0F)) * 4;
	ParseList.PackTotalLen = ToUint16(&Buffer[2]);
	ParseList.Id = ToUint16(&Buffer[4]);
	ParseList.Flags = Buffer[6] >> 5;
	ParseList.FragmentOffset = ((uint16_t)(Buffer[6] & 0x1F) << 8) | Buffer[7];
	ParseList.TTL = Buffer[8];
	ParseList.Protocol = Buffer[9];
	ParseList.HeaderChecksum = ToUint16(&Buffer[10]);
	for (int i = 0; i < 4; i++) {
		ParseList.SrcAdd[i] = Buffer[12 + i];
	}
	for (int i = 0; i < 4; i++) {
		ParseList.DestAdd[i] = Buffer[16 + i];
	}
	return ParseList;
}

TCPHeader TCPParser(char *Buffer, uint32_t Len) {
	TCPHeader ParseList;
	if (Len < 20) {
		ParseList.ErrMsg = 1;
		return ParseList;
	}
	ParseList.SrcPort = ToUint16(&Buffer[0]);
	ParseList.DestPort = ToUint16(&Buffer[2]);
	ParseList.SeqNum = ToUint32(&Buffer[4]);
	ParseList.ACKNum = ToUint32(&Buffer[8]);
	ParseList.TCPHeadLen = (Buffer[12] >> 4) * 4;
	ParseList.Reserved = Buffer[12] & 0x0E;
	ParseList.Flags = Buffer[13];
	ParseList.Window = ToUint16(&Buffer[14]);
	ParseList.Checksum = ToUint16(&Buffer[16]);
	ParseList.UrgPtr = ToUint16(&Buffer[18]);
	return ParseList;
}

UDPHeader UDPParser(char *Buffer, uint32_t Len) {
	UDPHeader ParseList;
	if (Len < 8) {
		ParseList.ErrMsg = 1;
		return ParseList;
	}
	ParseList.SrcPort = ToUint16(&Buffer[0]);
	ParseList.DestPort = ToUint16(&Buffer[2]);
	ParseList.UDPHeadLen = ToUint16(&Buffer[4]);
	ParseList.Checksum = ToUint16(&Buffer[6]);
	return ParseList;
}

IPv4ARPHeader IPv4ARPParser(char *Buffer, uint32_t Len) {
	IPv4ARPHeader ParseList;
	if (Len < 28) {
		ParseList.ErrMsg = 1;
		return ParseList;
	}
	ParseList.HardwareType = ToUint16(&Buffer[0]);
	ParseList.ProtocolType = ToUint16(&Buffer[2]);
	ParseList.HardwareAddLen = Buffer[4];
	ParseList.ProtocolAddLen = Buffer[5];
	ParseList.Operation = ToUint16(&Buffer[6]);
	for (int i = 0; i < 6; i++) {
		ParseList.SrcHardwareAdd[i] = Buffer[8 + i];
	}
	for (int i = 0; i < 4; i++) {
		ParseList.SrcProtocolAdd[i] = Buffer[14 + i];
	}
	for (int i = 0; i < 6; i++) {
		ParseList.TagHardwareAdd[i] = Buffer[18 + i];
	}
	for (int i = 0; i < 4; i++) {
		ParseList.TagProtocolAdd[i] = Buffer[24 + i];
	}
	return ParseList;
}

uint16_t Checksum(char *Buffer, size_t Len) {
	uint32_t Sum = 0;
	size_t i;
	for (i = 0; i < Len - 1; i += 2) {
		Sum += (Buffer[i] << 8) | Buffer[i + 1];
	}
	if (Len % 2 != 0) {
		Sum += (Buffer[Len - 1] << 8);
	}
	while (Sum >> 16) {
		Sum = (Sum & 0xFFFF) + (Sum >> 16);
	}
	return (uint16_t)(~Sum);
}
