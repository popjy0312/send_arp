#include <stdio.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>   /*  for struct ether_header */
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <arpa/inet.h>  /* for inet_pton */
#include <string.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdlib.h>

struct __attribute__((packed)) arp_addr{
    struct ether_addr SenderMac;
    struct in_addr SenderIP;
    struct ether_addr TargetMac;
    struct in_addr TargetIP;
};

int GetLocalIP(struct in_addr* LocalIP, char* dev);
int GetLocalMac(struct ether_addr* LocalMac, char* dev);
int GetSenderMac(pcap_t *handle, struct ether_addr LocalMac, struct in_addr LocalIP, struct in_addr SenderIP, struct ether_addr* SMac);
int GenArpPacket(struct ether_addr DMac, struct ether_addr SMac, uint16_t OpCode, struct in_addr SenderIP,struct ether_addr SenderMac, struct in_addr TargetIP, struct ether_addr TargetMac, char** packet, uint32_t* size);
int AttackPacket(pcap_t* handle, struct ether_addr SenderMac, struct ether_addr LocalMac, struct in_addr TargetIP, struct in_addr SenderIP);

