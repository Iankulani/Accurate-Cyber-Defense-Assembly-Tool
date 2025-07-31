#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <time.h>

// Global variables for monitoring
static pcap_t *handle = NULL;
static char monitoring_ip[16] = {0};
static int is_monitoring = 0;

// Threat counters
static int port_scan_count = 0;
static int dos_count = 0;
static int ddos_count = 0;
static int udp_flood_count = 0;
static int http_flood_count = 0;
static int https_flood_count = 0;

// Function to start monitoring an IP
void start_monitoring(const char *ip) {
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter_exp[100];
    struct bpf_program fp;
    
    if (is_monitoring) {
        stop_monitoring();
    }
    
    strncpy(monitoring_ip, ip, sizeof(monitoring_ip)-1);
    
    // Open live pcap session
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return;
    }
    
    // Compile and apply filter for the target IP
    snprintf(filter_exp, sizeof(filter_exp), "host %s", ip);
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return;
    }
    
    is_monitoring = 1;
    printf("Started monitoring IP: %s\n", ip);
}

// Function to stop monitoring
void stop_monitoring() {
    if (handle != NULL) {
        pcap_close(handle);
        handle = NULL;
    }
    is_monitoring = 0;
    memset(monitoring_ip, 0, sizeof(monitoring_ip));
    printf("Monitoring stopped\n");
}

// Packet handler for threat detection
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Analyze packet for threats
    // This is a simplified version - real implementation would be more complex
    
    // Check for port scanning (multiple SYN packets to different ports)
    static time_t last_scan_time = 0;
    static int syn_count = 0;
    
    struct ip *ip_header = (struct ip*)(packet + 14); // Skip Ethernet header
    struct tcphdr *tcp_header = (struct tcphdr*)(packet + 14 + (ip_header->ip_hl << 2));
    
    if (tcp_header->th_flags & TH_SYN && !(tcp_header->th_flags & TH_ACK)) {
        time_t now = time(NULL);
        if (now - last_scan_time < 2) { // Multiple SYN packets in short time
            syn_count++;
            if (syn_count > 5) {
                printf("THREAT DETECTED: Port scanning activity\n");
                port_scan_count++;
                syn_count = 0;
            }
        } else {
            syn_count = 1;
        }
        last_scan_time = now;
    }
    
    // Check for UDP flood (many UDP packets)
    struct udphdr *udp_header = (struct udphdr*)(packet + 14 + (ip_header->ip_hl << 2));
    static int udp_packet_count = 0;
    static time_t last_udp_flood_check = 0;
    
    if (ip_header->ip_p == IPPROTO_UDP) {
        time_t now = time(NULL);
        if (now - last_udp_flood_check < 1) {
            udp_packet_count++;
            if (udp_packet_count > 100) { // Threshold for UDP flood
                printf("THREAT DETECTED: UDP flood detected\n");
                udp_flood_count++;
                udp_packet_count = 0;
            }
        } else {
            udp_packet_count = 0;
            last_udp_flood_check = now;
        }
    }
    
   
}

// Function to check for threats
void check_threats() {
    if (!is_monitoring) {
        printf("Error: No active monitoring\n");
        return;
    }
    
    // Process packets to detect threats
    pcap_loop(handle, 10, packet_handler, NULL);
    
    // Display threat summary
    printf("\nThreat Detection Summary:\n");
    printf("Port scanning attempts: %d\n", port_scan_count);
    printf("DoS attacks detected: %d\n", dos_count);
    printf("DDoS attacks detected: %d\n", ddos_count);
    printf("UDP floods detected: %d\n", udp_flood_count);
    printf("HTTP floods detected: %d\n", http_flood_count);
    printf("HTTPS floods detected: %d\n", https_flood_count);
}

// Function to ping an IP
void ping_ip(const char *ip) {
    char command[100];
    snprintf(command, sizeof(command), "ping -c 4 %s", ip);
    system(command);
}

// Function to trace route to an IP
void trace_route(const char *ip) {
    char command[100];
    snprintf(command, sizeof(command), "traceroute %s", ip);
    system(command);
}