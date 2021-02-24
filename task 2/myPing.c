/*****************************************************************************/
/*** myping.c                                                              ***/
/***                                                                       ***/
/*** Use the ICMP protocol to request "echo" from destination.             ***/
/*****************************************************************************/

#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <time.h>

#define PACKETSIZE 64
#define IP_DEST "8.8.8.8"

struct packet
{
	struct icmphdr hdr;
	char msg[PACKETSIZE - sizeof(struct icmphdr)];
};

struct protoent *proto = NULL;

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
void ping(struct sockaddr_in *addr)
{
	int i, sd;
	struct packet pckt;
	struct sockaddr_in r_addr;
	struct timeval t1, t2;

	bzero(&pckt, sizeof(pckt));

	sd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sd < 0)
	{
		perror("socket");
		return;
	}
	pckt.hdr.type = ICMP_ECHO;
	pckt.hdr.un.echo.id = getpid();
	for (i = 0; i < sizeof(pckt.msg) - 1; i++)
	{
		pckt.msg[i] = i + '0';
	}
	pckt.msg[i] = 0;
	pckt.hdr.un.echo.sequence = 0;
	pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));
	gettimeofday(&t1, NULL);
	while (1)
	{
		if (sendto(sd, &pckt, sizeof(pckt), 0, (struct sockaddr *)addr, sizeof(*addr)) <= 0)
		{
			perror("sendto");
		}
		else
		{
			break;
		}
	}

	socklen_t len = sizeof(r_addr);
	int byts = 0;
	byts = recvfrom(sd, &pckt, sizeof(pckt), 0, (struct sockaddr *)&r_addr, &len);
	while (byts <= 0)
	{
		byts = recvfrom(sd, &pckt, sizeof(pckt), 0, (struct sockaddr *)&r_addr, &len);
	}
	if (byts > 0)
	{
		printf("***Got message!***\n");
	}
	gettimeofday(&t2, NULL);
	double milli = (t2.tv_sec - t1.tv_sec) * 1000.0; 	// sec to ms
	double micro = (t2.tv_usec - t1.tv_usec);			// us to ms
	milli += micro / 1000.0;
	printf("The RTT in milliseconds is: %lf\n", milli);
	printf("The RTT in microseconds is: %lf\n", micro);

	close(sd);
}

/*--------------------------------------------------------------------*/
/*--- main - look up host and start ping processes.                ---*/
/*--------------------------------------------------------------------*/
int main(int count, char *strings[])
{
	struct hostent *hname;
	struct sockaddr_in addr;

	proto = getprotobyname("ICMP");
	hname = gethostbyname(IP_DEST);
	bzero(&addr, sizeof(addr));
	addr.sin_family = hname->h_addrtype;
	addr.sin_port = 0;
	addr.sin_addr.s_addr = *(long *)hname->h_addr;
	ping(&addr);
	return 0;
}