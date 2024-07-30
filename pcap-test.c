#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
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

void print_packet_info(const u_char* packet, struct pcap_pkthdr* header) {
    struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *)packet;
    struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
    struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *)(packet + sizeof(struct libnet_ethernet_hdr) + (ip_hdr->ip_hl * 4));

    printf("\nEthernet Header\n");
    printf("   Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2],
           eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
    printf("   Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2],
           eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);

    printf("IP Header\n");
    printf("   Src IP: %s\n", inet_ntoa(ip_hdr->ip_src));
    printf("   Dst IP: %s\n", inet_ntoa(ip_hdr->ip_dst));

    printf("TCP Header\n");
    printf("   Src Port: %d\n", ntohs(tcp_hdr->th_sport));
    printf("   Dst Port: %d\n", ntohs(tcp_hdr->th_dport));

    const u_char *payload = packet + sizeof(struct libnet_ethernet_hdr) + (ip_hdr->ip_hl * 4) + (tcp_hdr->th_off * 4);
    int header_size = sizeof(struct libnet_ethernet_hdr) + (ip_hdr->ip_hl * 4) + (tcp_hdr->th_off * 4);
    int payload_len = header->caplen - header_size;

    if (payload_len > 0) {
        printf("Payload (up to 20 bytes, actual length: %d bytes):\n", payload_len);
        for (int i = 0; i < payload_len && i < 20; i++) {
            printf("%02x ", payload[i]);
        }
        printf("\n");
    } else {
        printf("Payload (0 bytes)\n");
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

        struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
        if (ip_hdr->ip_p == IPPROTO_TCP) {
            print_packet_info(packet, header);
        }
    }

    pcap_close(pcap);
    return 0;
}

