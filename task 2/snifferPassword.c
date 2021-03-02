/*****************************************************************************/
/*** sniffer.c                                                             ***/
/***                                                                       ***/
/*** Sniffer to message thet use ICMP protocols.                           ***/
/*****************************************************************************/

#include <pcap.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <linux/if_ether.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

/*--------------------------------------------------------------------*/
/*--- Extracts information from the packet that recived.           ---*/
/*--------------------------------------------------------------------*/
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
    struct sockaddr_in src, dest;
    src.sin_addr.s_addr = ip->saddr;
    dest.sin_addr.s_addr = ip->daddr;
    printf("The ip source is: %s\n", inet_ntoa(src.sin_addr));
    printf("The ip destination is: %s\n", inet_ntoa(dest.sin_addr));
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
    char *data = (char*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr));
    int size_data = 0;
    size_data = ntohs(ip->tot_len) - (sizeof(struct iphdr)) + sizeof(struct tcphdr);
    if (size_data>0){
        printf("%c", *data);
        printf("\n");
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter[] = "tcp and dst port 23";
    bpf_u_int32 net;


    // Open live pcap session on NIC with name br-fa2f4e6ce2dc
    handle = pcap_open_live("br-fa2f4e6ce2dc", BUFSIZ, 1, 1000, errbuf); 

    // Compile filter into BPF psuedo-code
    pcap_compile(handle, &fp, filter, 0, net);      
    pcap_setfilter(handle, &fp);                             

    // Capture packets
    pcap_loop(handle, -1, got_packet, NULL);                

    pcap_close(handle);   //Close the handle 
    return 0;
}