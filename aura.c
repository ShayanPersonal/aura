#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    
    struct ether_header *eth_header;
    print_packet_info(packet, *header);
    eth_header = (struct ether_header *) packet;
    int type = ntohs(eth_header->ether_type);
    switch (type) {
        case ETHERTYPE_IP:
            printf("IP\n");
            break;
        case ETHERTYPE_ARP:
            printf("ARP\n");
            break;
        case ETHERTYPE_REVARP:
            printf("Reverse ARP\n");
            break;
        default:
            printf("Unknown\n");
    }
}

int main(int argc, char *argv[]) {
    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    int timeout_limit = 10000; /* In milliseconds */

    device = pcap_lookupdev(error_buffer);
    if (device == NULL) {
        printf("Error finding device: %s\n", error_buffer);
    return 1;
                                                                 }

    /* Open device for live capture */
    handle = pcap_open_live(device, BUFSIZ, 0, timeout_limit, error_buffer);

    if (handle == NULL) {
        printf("Cannot open device %s: %s\n", device, error_buffer);
        return 2;
    }
    
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);

    return 0;
}
