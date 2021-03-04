/*****************************************************************************/
/*** sniffer.c                                                             ***/
/*****************************************************************************/

#include <pcap.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <linux/if_ether.h>

/*--------------------------------------------------------------------*/
/*--- print "Got Packet"           ---*/
/*--------------------------------------------------------------------*/
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    printf("Got Packet");
    printf("\n");
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter[] = "";
    bpf_u_int32 net;

    // Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf); 

    // Compile filter into BPF psuedo-code
    pcap_compile(handle, &fp, filter, 0, net);      
    pcap_setfilter(handle, &fp);                             

    // Capture packets
    pcap_loop(handle, -1, got_packet, NULL);                

    pcap_close(handle);   //Close the handle 
    return 0;
}