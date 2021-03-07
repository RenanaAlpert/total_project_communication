/*****************************************************************************/
/*** sniffAndSpoof.c                                                       ***/
/***                                                                       ***/
/*** Fake reply to request                                                 ***/
/*****************************************************************************/

#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; // destination host address 
  u_char  ether_shost[6]; // source host address 
  u_short ether_type;     // protocol type (IP, ARP, RARP, etc)
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4,     //IP header length
                     iph_ver:4;     //IP version
  unsigned char      iph_tos;       //Type of service
  unsigned short int iph_len;       //IP Packet length (data + header)
  unsigned short int iph_ident;     //Identification
  unsigned short int iph_flag:3,    //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl;       //Time to Live
  unsigned char      iph_protocol;  //Protocol type
  unsigned short int iph_chksum;    //IP datagram checksum
  struct  in_addr    iph_sourceip;  //Source IP address
  struct  in_addr    iph_destip;    //Destination IP address
};

/* ICMP Header  */
struct icmpheader {
  unsigned char icmp_type;        // ICMP message type
  unsigned char icmp_code;        // Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int icmp_id;     //Used for identifying request
  unsigned short int icmp_seq;    //Sequence number
};

/**********************************************
 * Calculating Checksum                    
 **********************************************/
unsigned short in_cksum (unsigned short *buf, int length)
{
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

   /*
    * The algorithm uses a 32 bit accumulator (sum), adds
    * sequential 16 bit words to it, and at the end, folds back all 
    * the carry bits from the top 16 bits into the lower 16 bits.
    */
   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

   /* treat the odd byte at the end, if any */
   if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }

   /* add back carry outs from top 16 bits to low 16 bits */
   sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16 
   sum += (sum >> 16);                  // add carry 
   return (unsigned short)(~sum);
}

/*************************************************************
  Given an IP packet, send it out using a raw socket.
**************************************************************/
void sendPacket(u_char *packet)
{
    struct ipheader *ipRequest;                      
    ipRequest = (struct ipheader *)(packet + sizeof(struct ethheader));
    struct icmpheader *icmpRequest = (struct icmpheader*)(packet + sizeof(struct ipheader));
    int ip_len = ntohs(ipRequest->iph_len);

    char buffer[ip_len];
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, (packet + sizeof(struct ethheader)), sizeof(buffer));

    char *buf = buffer;
    struct ipheader *ip = (struct ipheader*)(buf);
    struct icmpheader *icmp = (struct icmpheader*)(buf + sizeof(struct ipheader));

    struct sockaddr_in src, dest;
    src.sin_addr.s_addr = ipRequest->iph_destip.s_addr;
    dest.sin_addr.s_addr = ipRequest->iph_sourceip.s_addr;

    /*********************************************************
      Fill in the IP header.
    ********************************************************/
    ip->iph_sourceip.s_addr = src.sin_addr.s_addr;
    ip->iph_destip.s_addr = dest.sin_addr.s_addr;

    int icmp_len = ip_len-ipRequest->iph_ihl*4;

    /*********************************************************
      Fill in the ICMP header.
    ********************************************************/
    icmp->icmp_type = 0;  // ICMP type 0 is reply
    // Calculate the checksum for integrity
    icmp->icmp_chksum = 0;
    icmp->icmp_chksum = in_cksum((unsigned short *)icmp ,icmp_len);
    

    struct sockaddr_in dest_info;
    int enable = 1;
    dest_info.sin_family = AF_INET;

    inet_pton(AF_INET,inet_ntoa(ip->iph_sourceip),&dest_info.sin_addr.s_addr);
    dest_info.sin_port = ntohs(0);

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0)
    {
      printf("[-] failed Create a raw network socket");
      return;
    }

    // Step 2: Set socket option.
    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) < 0)
    {
      printf("[-] failed Set socket option");
      return;
    }

    // Step 4: Send the packet out.
    if(sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info)) < 0)
    {
      printf("[-] failed Send the packet out");
      return;
    }
    close(sock);
}

/*--------------------------------------------------------------------*/
/*--- Send Reply to the reguest thet recived                       ---*/
/*--------------------------------------------------------------------*/
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader)); 
    if(ip->iph_protocol == IPPROTO_ICMP){
      sendPacket(packet);
    }
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "icmp and src host 10.9.0.7";// machine we want
  bpf_u_int32 net;

  // Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

  // Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  pcap_setfilter(handle, &fp);

  // Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  //Close the handle
  pcap_close(handle);   
  return 0;
}

