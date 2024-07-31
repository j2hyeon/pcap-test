#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "my_header.h"

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test ens33\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    // 1. ETHERNET
    struct ethheader *eth = (struct ethheader *)packet;

    // 2. IP PACKET (0x0800)
    if (ntohs(eth->ether_type) == 0x0800)
    {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        // 3. TCP PROTOCOL
        if (ip->iph_protocol == IPPROTO_TCP)
        {
            printf("ETHERNET HEADER\n");
            printf("    src MAC: ");
            for (int i = 0; i < 6; i++)
            {
                if(i==5){
                  printf("%02x", eth->ether_shost[i]);
                }
                else{
                printf("%02x:", eth->ether_shost[i]);
                }
            }
            
            printf("\n    dst MAC: ");
            for (int i = 0; i < 6; i++)
            {
                if(i==5){
                  printf("%02x", eth->ether_dhost[i]);
                }
                else{
                printf("%02x:", eth->ether_dhost[i]);
                }
            }
            printf("\n");

            printf("IP HEADER\n");
            printf("    src IP: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("    dst IP: %s\n", inet_ntoa(ip->iph_destip));

            int ip_header_len = ip->iph_ihl * 4;
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);

            printf("TCP HEADER\n");
            printf("    src port: %d\n", ntohs(tcp->tcp_sport));
            printf("    dst port: %d\n", ntohs(tcp->tcp_dport));

            int header_length = TH_OFF(tcp) * 4;
            u_char *payload = ((u_char*)tcp) + header_length;
            int payload_len = ntohs(ip->iph_len) - (ip_header_len + header_length);

            if (payload_len > 0)
            {
                printf("TCP DATA (0x14):\n");
                for (int i = 0; i < payload_len && i < 20; i++)
                {
                    printf("%02x ", payload[i]);
                }
                printf("\n");
            }
            else
            {
                printf("TCP DATA: none\n");
            }
            printf("%u bytes captured\n", header->caplen);
            printf("\n----------------------------------------------\n");
        }
    }
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        got_packet(NULL, header, packet);

    }

    pcap_close(pcap);
}

