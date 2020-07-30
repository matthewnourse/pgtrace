#include <stdio.h>
#include <stdint.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <signal.h>
#include <errno.h>

#define PROGRAM_NAME "pgtrace"
#include "common.h"
#include "state_machine.h"
#include "tcp_state.h"
#include "test.h"

/* Ethernet header */
struct sniff_ethernet {
    u_char  ether_dhost[6];    /* destination host address */
    u_char  ether_shost[6];    /* source host address */
    u_short ether_type;        /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char  ip_vhl;                   /* version << 4 | header length >> 2 */
    u_char  ip_tos;                   /* type of service */
    u_short ip_len;                   /* total length */
    u_short ip_id;                    /* identification */
    u_short ip_off;                   /* fragment offset field */
#define PACKET_CAPTURE_SNIFF_IP_RF 0x8000 /* reserved fragment flag */
#define PACKET_CAPTURE_SNIFF_IP_DF 0x4000 /* dont fragment flag */
#define PACKET_CAPTURE_SNIFF_IP_MF 0x2000 /* more fragments flag */
#define PACKET_CAPTURE_SNIFF_IP_OFFMASK 0x1fff /* mask for fragmenting bits */
    u_char  ip_ttl;                   /* time to live */
    u_char  ip_p;                     /* protocol */
    u_short ip_sum;                   /* checksum */
    struct  in_addr ip_src,ip_dst;    /* source and dest address */
};

#define PACKET_CAPTURE_IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define PACKET_CAPTURE_IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char  th_offx2;               /* data offset, rsvd */
#define PACKET_CAPTURE_TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
#define PACKET_CAPTURE_TH_FIN  0x01
#define PACKET_CAPTURE_TH_SYN  0x02
#define PACKET_CAPTURE_TH_RST  0x04
#define PACKET_CAPTURE_TH_PUSH 0x08
#define PACKET_CAPTURE_TH_ACK  0x10
#define PACKET_CAPTURE_TH_URG  0x20
#define PACKET_CAPTURE_TH_ECE  0x40
#define PACKET_CAPTURE_TH_CWR  0x80
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};

tcp_state_t global_tcp_state;


static pcap_t *open_pcap_handle_from_file(const char *file_name) {
    ASSERT(file_name);
    char errbuf[PCAP_ERRBUF_SIZE];
    
    pcap_t *handle = pcap_open_offline(file_name, errbuf);
    if (!handle) {
        FATAL("Can't open file: %s.  Error: %s", file_name, errbuf);        
    }
    
    return handle;
}

static pcap_t *open_pcap_handle_from_device(const char *device) {
    ASSERT(device);    
    char errbuf[PCAP_ERRBUF_SIZE];    
    
    pcap_t *handle = pcap_create(device, errbuf);
    if (!handle) {
        FATAL("Can't open device: %s.  Error: %s", device, errbuf);
    }
    
    int result;
    if ((result = pcap_set_promisc(handle, 1)) != 0) {
        FATAL("pcap_set_promisc failed, result=%d", result);
    }
    
    if ((result = pcap_set_timeout(handle, 1000)) != 0) {
        FATAL("pcap_set_timeout failed, result=%d", result);
    }
    
    if ((result = pcap_set_snaplen(handle, 0xffff)) != 0) {
        FATAL("pcap_set_snaplen failed, result=%d", result);
    }
    
    size_t buffer_size = 50 * 1024 * 1024;
    if ((result = pcap_set_buffer_size(handle, buffer_size)) != 0) {
        FATAL("pcap_set_buffer_size failed.  buffer_size=%zu, result=%d", buffer_size, result);
    }
    
    if ((result = pcap_activate(handle)) != 0) {
        FATAL("pcap_activate failed, result=%d", result);
    }
    
    return handle;
}

static void close_pcap_handle(pcap_t *handle) {
    ASSERT(handle);
    pcap_close(handle);
}

static void set_bpf_filter(pcap_t *pcap_handle, const char *device, const char *filter, struct bpf_program *bpf) {
    const bool optimize = true;
    bpf_u_int32 device_mask;
    bpf_u_int32 device_ip;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_lookupnet(device, &device_ip, &device_mask, errbuf) == -1) {
        FATAL("Can't get IP & netmask for device: %s.  Error: %s", device, errbuf);
    }

    if (pcap_compile(pcap_handle, bpf, filter, optimize, device_mask) == -1) {
        FATAL("Can't parse filter: '%s'.  Error: %s", filter, pcap_geterr(pcap_handle));
    }

    if (pcap_setfilter(pcap_handle, bpf) == -1) {
        FATAL("Can't install filter: '%s'.  Error: %s", filter, pcap_geterr(pcap_handle));
    }
}


static void on_packet(u_char *ctx_uc, const struct pcap_pkthdr *header, const u_char *packet) {
    set_now(&header->ts);
    
    /* declare pointers to packet headers */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    const u_char *payload;                  /* Packet payload */

    int size_ip;
    int size_tcp;
    int size_payload;

    /* define/compute ip header offset */
    ASSERT(sizeof(struct sniff_ethernet) == 14);
    ip = (struct sniff_ip*)(packet + sizeof(struct sniff_ethernet));
    size_ip = PACKET_CAPTURE_IP_HL(ip)*4;
    if (size_ip < 20) {
        // Invalid IP header length.
        return;
    }

    /* determine protocol */
    switch (ip->ip_p) {
        case IPPROTO_TCP:
          break;
  
        case IPPROTO_UDP:
          // Not supported yet (HTTP/3?!)
          return;
  
        case IPPROTO_ICMP:
        case IPPROTO_IP:
        default:
          return;
    }

    /* OK, this packet is TCP. */
    /* define/compute tcp header offset */
    tcp = (struct sniff_tcp*)(packet + sizeof(struct sniff_ethernet) + size_ip);
    size_tcp = PACKET_CAPTURE_TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        // Invalid TCP header length.
        return;
    }

    /* NOTE that this code doesn't support ipv6. */
    char source_address[INET_ADDRSTRLEN + 1];
    char dest_address[INET_ADDRSTRLEN + 1];
    memset(source_address, 0, sizeof(source_address));
    memset(dest_address, 0, sizeof(dest_address));

    inet_ntop(AF_INET, &ip->ip_src, source_address, sizeof(source_address) - 1);
    inet_ntop(AF_INET, &ip->ip_dst, dest_address, sizeof(dest_address) - 1);

    uint16_t source_port = ntohs(tcp->th_sport);
    uint16_t dest_port = ntohs(tcp->th_dport);

    /* define/compute tcp payload (segment) offset */
    payload = (u_char *)(packet + sizeof(struct sniff_ethernet) + size_ip + size_tcp);

    /* compute tcp payload (segment) size */
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
    if (size_payload < 0) {
        /* ip_len is invalid. */        
        return;
    }

    tcp_seq seq = ntohl(tcp->th_seq);
    tcp_seq ack = ntohl(tcp->th_ack);
    u_short window = ntohs(tcp->th_win);
    LOG("source_port=%u dest_port=%u seq=%u ack=%u window=%u size_payload=%d flags=0x%02x",
        source_port, dest_port, seq, ack, window, size_payload, tcp->th_flags); 
    
    const u_char *payload_end = payload + size_payload;
    const u_char *payload_p = payload;
    /*TODO: a fancier means of figuring out who the server is. */
    if (5432 == source_port) {
        if ((tcp->th_flags & PACKET_CAPTURE_TH_SYN) != 0) {
            /* It's the first packet in a connection. */
            tcp_state_set_be_seq_range(&global_tcp_state, dest_port, seq, 0);
        }
        
        if (tcp_state_is_be_packet_in_sequence(&global_tcp_state, dest_port, seq, size_payload)) {
            for (; payload_p < payload_end; ++payload_p) {        
                state_machine_be_next(source_port, dest_port, *payload_p, size_payload, stdout);
            }
        }
        
        if ((tcp->th_flags & PACKET_CAPTURE_TH_ACK) != 0) {
            tcp_state_set_fe_seq_range(&global_tcp_state, dest_port, ack, window);
        }
    } else {
        if ((tcp->th_flags & PACKET_CAPTURE_TH_SYN) != 0) {
            /* It's the first packet in a connection. */
            tcp_state_set_fe_seq_range(&global_tcp_state, source_port, seq, 0);
        }
        
        if (tcp_state_is_fe_packet_in_sequence(&global_tcp_state, source_port, seq, size_payload)) {
            for (; payload_p < payload_end; ++payload_p) {        
                state_machine_fe_next(source_port, dest_port, *payload_p, size_payload, stdout);
            }
        }
        
        if ((tcp->th_flags & PACKET_CAPTURE_TH_ACK) != 0) {
            tcp_state_set_be_seq_range(&global_tcp_state, source_port, ack, window);
        }
    }
}

pcap_t *global_pcap_handle;

static void print_stats() {
    struct pcap_stat ps;
    if (pcap_stats(global_pcap_handle, &ps) != 0) {
        LOG("pcap_stats failed. Error: %s", pcap_geterr(global_pcap_handle));
    } else {
        LOG("pcap_stats: ps_recv: %u  ps_drop: %u  ps_ifdrop: %u", ps.ps_recv, ps.ps_drop, ps.ps_ifdrop);
    }
}

static void signal_handler(int sig, siginfo_t *siginfo, void *context) {
	if (SIGUSR1 == sig) {
        print_stats();
        fflush(stdout);
    } 
}

static void install_signal_handler() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = signal_handler;
    sa.sa_flags = SA_SIGINFO;
    if (sigaction(SIGUSR1, &sa, NULL) < 0) {
        FATAL("sigaction failed, errno=%d", errno);
    }
}

static void set_big_output_buffer() {
    if (setvbuf(stdout, NULL, _IOFBF, 256 * 1024) != 0) {
        FATAL("setvbuf failed, errno=%d", errno);
    }
}

int main(const int argc, const char *argv[]) {
    if ((argc != 2) && (argc != 3)) {
        fprintf(stderr, "Usage: %s device_to_sniff pcap_filter_string\n", PROGRAM_NAME);
        fprintf(stderr, "OR:    %s pcap_file\n", PROGRAM_NAME);
        fprintf(stderr, "Use kill -SIGUSR1 to tell it to print stats & flush its output buffer.\n");
        return 1;
    }
    
    const char *device_or_file = argv[1];
    const char *filter = (argc < 3) ? NULL : argv[2];
    
    tcp_state_init(&global_tcp_state);
    install_signal_handler();
    set_big_output_buffer();
    
    test();    
    LOG("Self-test complete. device_or_file='%s' filter='%s'", device_or_file, filter);    

    struct bpf_program bpf;
    
    if (filter) {
        global_pcap_handle = open_pcap_handle_from_device(device_or_file);
        set_bpf_filter(global_pcap_handle, device_or_file, filter, &bpf);
    } else {
        global_pcap_handle = open_pcap_handle_from_file(device_or_file);
    }
    
    int link_layer_header_type = pcap_datalink(global_pcap_handle);
    if (link_layer_header_type != DLT_EN10MB) {
        FATAL("Unsupported link-layer header type: %d.  Only Ethernet(%d) is supported", link_layer_header_type, DLT_EN10MB);
    }
    
    state_machine_init();
    
    int max_num_packets = -1;
    u_char *context = NULL;
    if (pcap_loop(global_pcap_handle, max_num_packets, on_packet, context) == -1) {
        FATAL("pcap_loop failed.  Error: %s", pcap_geterr(global_pcap_handle));
    }
    
    if (filter) {
        pcap_freecode(&bpf);
    }
    
    close_pcap_handle(global_pcap_handle);    
    return 0;
}
