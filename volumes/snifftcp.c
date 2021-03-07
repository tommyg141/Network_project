#include <pcap.h>
#include <stdio.h>
/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; 
  u_char  ether_shost[6]; 
  u_short ether_type;     
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, 
                     iph_ver:4; 
  unsigned char      iph_tos; 
  unsigned short int iph_len; 
  unsigned short int iph_ident; 
  unsigned short int iph_flag:3, 
                     iph_offset:13; 
  unsigned char      iph_ttl; 
  unsigned char      iph_protocol; 
  unsigned short int iph_chksum; 
  struct  in_addr    iph_sourceip; 
  struct  in_addr    iph_destip;   
};

void got_packet(u_char*args, const struct pcap_pkthdr*header,const u_char*packet){
struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 

    printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("         To: %s\n", inet_ntoa(ip->iph_destip)); 
    /* determine protocol */
    switch(ip->iph_protocol) {                                 
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            return;
     
    }
  }}
int main(){
pcap_t*handle;
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;
char filter_exp[] = "tcp and dst portrange 10-100";
bpf_u_int32 net;
handle = pcap_open_live("br-e677e91290db", BUFSIZ, 1, 1000, errbuf);
pcap_compile(handle, &fp, filter_exp, 0, net);
pcap_setfilter(handle, &fp);
pcap_loop(handle, -1, got_packet, NULL);
pcap_close(handle);   

return 0;
}

