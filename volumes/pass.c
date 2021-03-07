#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "myheader.h"
/* Ethernet header */

void got_packet(u_char*args, const struct pcap_pkthdr*header,const u_char*packet){
int i =0 ;
int size_data=0;
printf("\nGot a packet\n");

struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 
      struct tcpheader *tcp = (struct tcpheader *)(packet +sizeof(struct ethheader)+sizeof(struct ipheader));
 	if(ip->iph_protocol==IPPROTO_TCP && ntohs(tcp->tcp_dport)==23){
    printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("         To: %s\n", inet_ntoa(ip->iph_destip));    

   printf("      source port: %d\n" , ntohs(tcp->tcp_sport));
   printf("      destiantion port: %d\n" , ntohs (tcp->tcp_dport));
   
    /* determine protocol */
    switch(ip->iph_protocol) {                                 
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            break;
     }
     char *data = (u_char*)packet +sizeof(struct ethheader)+sizeof(struct ipheader)+sizeof(struct tcpheader);
     size_data =ntohs(ip->iph_len)-(sizeof(struct ipheader)+sizeof(struct tcpheader));
     if(size_data>0){
     printf("   payload(%d bytes):\n",size_data);
     for (i=0; i<size_data; i++){
     if(isprint(*data))
   	printf("%c",*data);
   //  if(data[i]>'a' && data[i]<'z')
     //		printf("%c",data[i]);
     else
     	printf(".");
     data++;			
  }}}
  return;
  }}
int main(){
pcap_t*handle;
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;
char filter_exp[] = "porto TCP and  dst portrange 10-100";
bpf_u_int32 net;

handle = pcap_open_live("br-e677e91290db", BUFSIZ, 1, 1000, errbuf);

pcap_compile(handle, &fp, filter_exp, 0, net);
pcap_setfilter(handle, &fp);
pcap_loop(handle, -1, got_packet, NULL);
pcap_close(handle);   

return 0;
}

