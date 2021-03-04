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
	//struct iphdr *iphdr;
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
void reply(struct sockaddr_in *addr, struct packet *pckt)
{
	int sd;

	sd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sd < 0)
	{
		perror("socket");
		return;
	}

	if (sendto(sd, &pckt, sizeof(pckt), 0, (struct sockaddr *)addr, sizeof(*addr)) <= 0)
	{
		perror("sendto");
	}

	close(sd);
}

/*--------------------------------------------------------------------*/
/*--- Extracts information from the packet that recived			   ---*/
/*--- and send reply.                                               ---*/
/*--------------------------------------------------------------------*/
void extractInfo(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct iphdr *ipreq = (struct iphdr *)(packet + sizeof(struct ethhdr));
	struct sockaddr_in src, dest;
	bzero(&dest, sizeof(dest));
	src.sin_addr.s_addr = ipreq->daddr;
	dest.sin_addr.s_addr = ipreq->saddr;
	printf("The ip source of the request is: %s\n", inet_ntoa(dest.sin_addr));
	printf("The ip destination of the request is: %s\n", inet_ntoa(src.sin_addr));
	struct icmphdr *icmpreq = (struct icmphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
	printf("The type of icmp of the request is: %d\n", icmpreq->type);
	printf("The code of icmp of the request is: %d\n", icmpreq->code);
	printf("\n");

	
	dest.sin_family = AF_INET;
	dest.sin_port = 0;

	struct packet pckt;
	bzero(&pckt, sizeof(pckt));

	//pckt.iphdr->daddr = ipreq->saddr;
	//pckt.iphdr->id = ipreq->id;
	//pckt.iphdr->protocol = IPPROTO_ICMP;
	//pckt.iphdr->saddr = ipreq->daddr;

	pckt.icmphdr.type = ICMP_ECHOREPLY;
	pckt.icmphdr.un.echo.id = icmpreq->un.echo.id;
	pckt.icmphdr.un.echo.sequence = icmpreq->un.echo.sequence;
	pckt.icmphdr.checksum = checksum(&pckt, sizeof(pckt));
	//pckt.msg = *(packet + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr));

	reply(&dest, &pckt);
}

int main()
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter[] = "icmp";
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