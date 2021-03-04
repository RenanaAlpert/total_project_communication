/*****************************************************************************/
/*** myping.c                                                              ***/
/***                                                                       ***/
/*** Use the ICMP protocol to request "echo" from destination.             ***/
/*****************************************************************************/

#include <pcap.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <linux/if_ether.h>

#define PACKETSIZE 1024

struct packet
{
	struct iphdr *iphdr;
	struct icmphdr icmphdr;
	char msg[PACKETSIZE - sizeof(struct icmphdr)];
};

//struct protoent *proto = NULL;

/*--------------------------------------------------------------------*/
/*--- checksum - standard 1s complement checksum                   ---*/
/*--------------------------------------------------------------------*/
unsigned short checksum(void *b, int len)
{
	unsigned short *buf = b;
	unsigned int sum = 0;
	unsigned short result;

	for (sum = 0; len > 1; len -= 2)
		sum += *buf++;
	if (len == 1)
		sum += *(unsigned char *)buf;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}

/*--------------------------------------------------------------------*/
/*--- ping - Create message and send it.                           ---*/
/*--------------------------------------------------------------------*/
void reply(struct sockaddr_in *addr, u_char *pckt)
{
	printf("reply\n");

	int sd;
	sd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sd < 0)
	{
		perror("[-] socket fail\n");
		return;
	}
	printf("[+] open socket\n");

	if (sendto(sd, &pckt, sizeof(pckt), 0, (struct sockaddr *)addr, sizeof(*addr)) <= 0)
	{
		perror("[-] sendto fail\n");
	}
	printf("[+] send reply\n");
	printf("\n");

	close(sd);
}

/*--------------------------------------------------------------------*/
/*--- Extracts information from the packet that recived			   ---*/
/*--- and send reply.                                               ---*/
/*--------------------------------------------------------------------*/
void extractInfo(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct ethhdr *ethreq = (struct ethhdr *)packet;
	struct iphdr *ipreq = (struct iphdr *)(packet + sizeof(struct ethhdr));
	struct icmphdr *icmpreq = (struct icmphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
	struct sockaddr_in src, dest;
	bzero(&dest, sizeof(dest));
	src.sin_addr.s_addr = ipreq->saddr;
	dest.sin_addr.s_addr = ipreq->daddr;
	printf("The ip source of the request is: %s\n", inet_ntoa(src.sin_addr));
	printf("The ip destination of the request is: %s\n", inet_ntoa(dest.sin_addr));
	printf("The type of icmp of the request is: %d\n", icmpreq->type);
	printf("The code of icmp of the request is: %d\n", icmpreq->code);
	printf("\n");

	if (icmpreq->type == 8)
	{
		for (int i = 0; i < 6; ++i)
		{ // swap source and destination MACs
			int bkp = ethreq->h_source[i];
			ethreq->h_source[i] = ethreq->h_dest[i];
			ethreq->h_dest[i] = bkp;
		}

		ipreq->saddr = ipreq->daddr;
		ipreq->daddr = src.sin_addr.s_addr;

		src.sin_family = AF_INET;
		src.sin_port = ICMP_ECHOREPLY;

		icmpreq->type = 0;
		//icmpreq->checksum = checksum(packet, sizeof(packet));
		reply(&src, packet);
	}

	/*struct packet pckt;
	bzero(&pckt, sizeof(pckt));

	pckt.iphdr->daddr = ipreq->saddr;
	pckt.iphdr->id = ipreq->id;
	pckt.iphdr->protocol = IPPROTO_ICMP;
	pckt.iphdr->saddr = ipreq->daddr;

	pckt.icmphdr.type = ICMP_ECHOREPLY;
	pckt.icmphdr.un.echo.id = icmpreq->un.echo.id;
	pckt.icmphdr.un.echo.sequence = icmpreq->un.echo.sequence;
	pckt.icmphdr.checksum = checksum(&pckt, sizeof(pckt));
	//pckt.msg = *(packet + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr));*/
}

int main()
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter[] = "icmp[icmptype] == 8 or icmp[icmptype] == 0";
	bpf_u_int32 net;

	// Open live pcap session on NIC with name enp0s3.
	handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

	// Compile filter into BPF psuedo-code
	pcap_compile(handle, &fp, filter, 0, net);
	pcap_setfilter(handle, &fp);

	// Capture packets
	pcap_loop(handle, -1, extractInfo, NULL);

	pcap_close(handle); //Close the handle
	return 0;
}