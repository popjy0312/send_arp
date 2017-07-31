#include <stdio.h>
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

int GetMyMac(struct ether_addr* MyMac, char* dev);
int GetSenderMac(struct ether_addr* SMac);
int GenArpPacket(struct ether_addr DMac, struct ether_addr SMac, char OpCode, struct in_addr SenderIP,struct ether_addr SenderMac, struct in_addr TargetIP, struct ether_addr TargetMac, char** packet, int* size);
int SpoofPacket(pcap_t* handle, struct ether_addr SenderMac, struct ether_addr MyMac, struct in_addr TargetIP, struct in_addr SenderIP);

int main(int argc, char** argv){
    pcap_t *handle;   /* Session handle */
    char *dev;  /* device to communication */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
    struct ether_addr MyMac;   /* my mac address */
    struct ether_addr SenderMac;
    struct in_addr SenderIP, TargetIP;
    /* Check argument count */
    if(argc != 4){
        printf("usage : %s <interface> <sender ip> <target ip>\n",argv[0]);
        return -1;
    }
    if(inet_pton(AF_INET, argv[2], &SenderIP) != 1){
        printf("usage : %s <interface> <sender ip> <target ip>\n",argv[0]);
        return -1;
    }
    if(inet_pton(AF_INET, argv[3], &TargetIP) != 1){
        printf("usage : %s <interface> <sender ip> <target ip>\n",argv[0]);
        return -1;
    }
    /* Define device */
    dev = argv[1];
    /* Open session in promiscuous mode */
    if( (handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf)) == NULL){
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }
    printf("Get Local Mac Address...\n");
    if(GetMyMac(&MyMac, dev) != 1){
        fprintf(stderr, "Couldn't Get local Mac Address\n");
        return 2;
    }
    printf("Local Mac Address is %s\n",ether_ntoa(&MyMac));
    GetSenderMac(&SenderMac);
    //SpoofPacket(handle,SenderMac,MyMac,TargetIP,SenderIP);
    return 0;
}

/* Ref: https://stackoverflow.com/questions/1779715/how-to-get-mac-address-of-your-machine-using-a-c-program */
int GetMyMac(struct ether_addr* MyMac, char* dev){
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, dev);
    if (ioctl(fd, SIOCGIFHWADDR, &s) == 0) {
        memcpy(MyMac, s.ifr_addr.sa_data, ETHER_ADDR_LEN);
        return 1;
    }
    return 0;
}

int GetSenderMac(struct ether_addr* SMac){
    char *packet;
    int size;
    /* broadcast request packet */
    //GenArpPacket(BroadcastMac, MyMac, ARPOP_REQUEST, MyIP, SenderIP, &packet, &size);
    /* parsing sniffed packet */
    return 1;
}



int GenArpPacket(struct ether_addr DMac, struct ether_addr SMac, char OpCode, struct in_addr SenderIP,struct ether_addr SenderMac, struct in_addr TargetIP, struct ether_addr TargetMac, char** packet, int* size){
    struct ether_arp eth_arp;

    eth_arp.arp_hrd = htons(ARPHRD_ETHER);
    eth_arp.arp_pro = htons(ETHERTYPE_IP);
    eth_arp.arp_hln = 6;
    eth_arp.arp_pln = 4;
    eth_arp.arp_op = OpCode;
    memcpy(eth_arp.arp_sha, &SenderMac, ETH_ALEN);
    memcpy(eth_arp.arp_spa, &SenderIP, 4);
    memcpy(eth_arp.arp_tha, &TargetMac, ETH_ALEN);
    memcpy(eth_arp.arp_tpa, &TargetIP, 4);

    *size = sizeof(struct ether_arp);
    memcpy(*packet, &eth_arp, sizeof(struct ether_arp));
    /* for debug */
    int i;
    for(i=0;i<*size;i++){
        printf("%02x ",(*packet)[i]);
    }
    return 1;
}

int SpoofPacket(pcap_t* handle, struct ether_addr SenderMac, struct ether_addr MyMac, struct in_addr TargetIP, struct in_addr SenderIP){
    char *packet;
    int size;
    GenArpPacket(SenderMac,MyMac,ARPOP_REPLY,TargetIP,MyMac,SenderIP,SenderMac,&packet,&size);
    pcap_sendpacket(handle,packet,size);
    return 1;
}
