#include <stdio.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>

void rfmon_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
)
{
    struct ether_header* ether_packet;
    struct ether_addr* destination;
    struct ether_addr* source;

    printf("Total packet available: %d bytes\n", header->caplen);
    printf("Expected packet size: %d bytes\n", header->len);

    for (int i = 0; i < header->caplen; i++) {
        printf("%x", *(packet + i));
    }
    printf("\n");

    ether_packet = (struct ether_header *) (packet + 28);
    destination = (struct ether_addr *) ether_packet->ether_dhost;
    source = (struct ether_addr *) ether_packet->ether_shost;

    printf("%u\n", ntohs(ether_packet->ether_type));

    printf("Desination: %s\n", ether_ntoa(destination));
    printf("Source: %s\n", ether_ntoa(source));
    
    return;
}

int main(int argc, char **argv) {    
    char *device = "wlan0";
    char error_buffer[PCAP_ERRBUF_SIZE];
    char filter_exp[] = "wlan type mgt subtype probe-req";
    int snapshot_length = 65535;
    int total_packet_count = -1;
    int timeout = -1;
    u_char *my_arguments = NULL;
    pcap_t *handle;
    bpf_u_int32 subnet_mask, ip;
    struct bpf_program filter;

    handle = pcap_create(device, error_buffer);
    pcap_set_rfmon(handle, 1);
    pcap_set_promisc(handle, 1);
    pcap_set_snaplen(handle, snapshot_length);
    pcap_set_timeout(handle, timeout);
    pcap_activate(handle);


    if (pcap_lookupnet(device, &ip, &subnet_mask, error_buffer) == -1) {
        printf("Could not get information for device: %s\n", device);
        ip = 0;
        subnet_mask = 0;
    }

    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
        printf("Bad filter - %s\n", pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        printf("Error setting filter - %s\n", pcap_geterr(handle));
        return 2;
    }

    if (pcap_loop(handle, total_packet_count, rfmon_handler, my_arguments) < 0)
        printf("pcap_loop failed: %s\n", pcap_geterr(handle));

    return 0;
}
