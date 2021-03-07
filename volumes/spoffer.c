#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET sizeof(struct ethhdr)

/* Spoofed packet containing only IP and ICMP headers */
struct spoofed_packet
{
    struct ip iph;
    struct icmp icmph;
};

#include <pcap.h>
#include <stdio.h>

unsigned short in_cksum(unsigned short *addr, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(unsigned char *) (&answer) = *(unsigned char *) w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}

/* This function will be invoked by pcap for each captured packet.
We can process each packet inside the function.
*/
void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
printf("Got a packet\n");
static int count = 1;                   /* packet counter */

	int s;	// socket
	const int on = 1;

	/* declare pointers to packet headers */
	const struct ether_header *ethernet = (struct ether_header*)(packet);
	const struct ip *iph;              /* The IP header */
	const struct icmp *icmph;            /* The ICMP header */
	struct sockaddr_in dst;

	int size_ip;

	/* define/compute ip header offset */
	iph = (struct ip*)(packet + SIZE_ETHERNET);
	size_ip = iph->ip_hl*4;	// size of ip header

	if (iph->ip_p != IPPROTO_ICMP || size_ip < 20) {  // disregard other packets
		return;
	}

	/* define/compute icmp header offset */
	icmph = (struct icmp*)(packet + SIZE_ETHERNET + size_ip);

	/* print source and destination IP addresses */
	printf("%d) ICMP Sniffing source: from--%s\n", count, inet_ntoa(iph->ip_src) );
  printf("   ICMP Sniffing destination: to--%s\n\n", inet_ntoa(iph->ip_dst) );

	/* Construct the spoof packet and allocate memory with the lengh of the datagram */
	char buf[htons(iph->ip_len)];
	struct spoofed_packet *spoof = (struct spoofed_packet *) buf;

	/* Initialize the structure spoof by copying everything in request packet to spoof packet*/
	memcpy(buf, iph, htons(iph->ip_len));
	/* Modify ip header */

   	//swap the destination ip address and source ip address
	(spoof->iph).ip_src = iph->ip_dst;
	(spoof->iph).ip_dst = iph->ip_src;

    	//recompute the checksum, you can leave it to 0 here since RAW socket will compute it for you.
	(spoof->iph).ip_sum = 0;

	/* Modify icmp header */

	// set the spoofed packet as echo-reply
	(spoof->icmph).icmp_type = ICMP_ECHOREPLY;
	// always set code to 0
	(spoof->icmph).icmp_code = 0;

	(spoof->icmph).icmp_cksum = 0;	// should be set as 0 first to recalculate.
	(spoof->icmph).icmp_cksum = in_cksum((unsigned short *) &(spoof->icmph), sizeof(spoof->icmph));
	//print the forged packet information
	printf("Spoofed packet src is %s\n",inet_ntoa((spoof->iph).ip_src));
	printf("Spoofed packet dest is %s\n\n",inet_ntoa((spoof->iph).ip_dst));

	memset(&dst, 0, sizeof(dst));
    	dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = (spoof->iph).ip_dst.s_addr;

	/* create RAW socket */
	if((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        printf("socket() error");
		return;
	}

	/* socket options, tell the kernel we provide the IP structure */
	if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
		printf("setsockopt() for IP_HDRINCL error");
		return;
	}

	if(sendto(s, buf, sizeof(buf), 0, (struct sockaddr *) &dst, sizeof(dst)) < 0) {
		printf("sendto() error");
	}

  printf("Spoofed Packet sent successfully\n");
	//close(s);	// free resource

	//free(buf);
	count++;
return;
}
int main()
{
pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;
char filter_exp[] = "ip proto icmp";
bpf_u_int32 net;
// Step 1: Open live pcap session on NIC with name eth3
//Students needs to change "eth3" to the name
//found on their own machines (using ifconfig).
handle = pcap_open_live("br-e677e91290db", BUFSIZ, 1, 1000, errbuf);
// Step 2: Compile filter_exp into BPF psuedo-code
pcap_compile(handle, &fp, filter_exp, 0, net);
pcap_setfilter(handle, &fp);
// Step 3: Capture packets
pcap_loop(handle, -1, got_packet, NULL);
pcap_close(handle);
return 0;}
