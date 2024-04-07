#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

void packet_capture(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    if (header->len < ETHER_HDR_LEN) {
        printf("Invalid Ethernet header length\n");
        return;
    }

    const u_char* eth_header = packet;

    // Ethernet 헤더 정보 출력
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth_header[6], eth_header[7], eth_header[8], eth_header[9], eth_header[10], eth_header[11]);
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth_header[0], eth_header[1], eth_header[2], eth_header[3], eth_header[4], eth_header[5]);

    printf("\n");
}

int main() {
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 1;
    }

    pcap_loop(handle, 0, packet_capture, NULL);

    pcap_close(handle);

    return 0;
}