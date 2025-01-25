#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <time.h>
#include <string.h>
// Global variable to count packets
static int packet_count = 0;

// Function prototypes
void list_devices(pcap_if_t **alldevs, char *error_buffer);
pcap_t *open_device(pcap_if_t *device, char *error_buffer);
void start_packet_capture(pcap_t *handle, int capture_duration);
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);
void process_packet_details(const struct pcap_pkthdr *header, const u_char *packet);

// Main function
int main() {
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs = NULL;
    pcap_t *handle;
    int capture_duration = 10; // Capture duration in seconds

    // List devices and select one
    list_devices(&alldevs, error_buffer);

    // Use the first available device
    if (alldevs == NULL) {
        fprintf(stderr, "No devices found.\n");
        return 1;
    }
    printf("Capturing packets on device: %s\n", alldevs->name);

    // Open the selected device for capturing
    handle = open_device(alldevs, error_buffer);
    if (handle == NULL) {
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Free the device list as it's no longer needed
    pcap_freealldevs(alldevs);

    // Start capturing packets
    start_packet_capture(handle, capture_duration);

    // Close the handle
    pcap_close(handle);
    return 0;
}

// Function to list devices
void list_devices(pcap_if_t **alldevs, char *error_buffer) {
    if (pcap_findalldevs(alldevs, error_buffer) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", error_buffer);
    }
}

// Function to open a device for packet capturing
pcap_t *open_device(pcap_if_t *device, char *error_buffer) {
    pcap_t *handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", error_buffer);
    }
    return handle;
}

// Function to start packet capturing
void start_packet_capture(pcap_t *handle, int capture_duration) {
    printf("Starting packet capture for %d seconds. Press Ctrl+C to stop.\n", capture_duration);
    
    time_t start_time = time(NULL);
    while (time(NULL) - start_time < capture_duration) {
        pcap_dispatch(handle, 1, packet_handler, NULL);
    }

    printf("\nTotal packets captured in %d seconds: %d\n", capture_duration, packet_count);
}

// Callback function to process each packet
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    packet_count++;
    process_packet_details(header, packet);
}

// Function to process and print packet details
void process_packet_details(const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    char protocol[10];

    // Convert timestamp to human-readable format
    time_t rawtime = header->ts.tv_sec;
    struct tm *timeinfo = localtime(&rawtime);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);

    // Extract IP header
    ip_header = (struct ip *)(packet + 14); // Skip Ethernet header (14 bytes)
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    // Determine protocol and parse headers accordingly
    if (ip_header->ip_p == IPPROTO_TCP) {
        strcpy(protocol, "TCP");
        tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl * 4));
        printf("Source Port: %d\n", ntohs(tcp_header->source));
        printf("Destination Port: %d\n", ntohs(tcp_header->dest));
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        strcpy(protocol, "UDP");
        udp_header = (struct udphdr *)(packet + 14 + (ip_header->ip_hl * 4));
        printf("Source Port: %d\n", ntohs(udp_header->source));
        printf("Destination Port: %d\n", ntohs(udp_header->dest));
    } else {
        strcpy(protocol, "Other");
    }

    // Print packet details
    printf("\nPacket Details:\n");
    printf("Timestamp: %s\n", timestamp);
    printf("Packet Size: %d bytes\n", header->len);
    printf("Protocol: %s\n", protocol);
    printf("Source IP: %s\n", src_ip);
    printf("Destination IP: %s\n", dst_ip);
    printf("TTL: %d\n", ip_header->ip_ttl);
    printf("\n");
}
