#!/usr/bin/python
from scapy.all import *
 
def spoof_pkt(pkt):
    newseq = 0
    ##if arp in pkt :
    if ICMP in pkt:
        print("Original Packet.........")
        print("Source IP: ", pkt[IP].src)
        print("Destination IP: ", pkt[IP].dst)
 
        srcip = pkt[IP].src
        dstip = pkt[IP].dst
        newihl = pkt[IP].ihl
        newtype = 0
        newid = pkt[ICMP].id
        newseq = pkt[ICMP].seq
        data = pkt[Raw].load
       
        IPLayer = IP(src=srcip,dst=dstip,ihl=newihl)
       
        ICMPpkt = ICMP(type=newtype,id=newid,seq=newseq)
        newpkt = IPLayer/ICMPpkt/data
 
        print ("Spoofing Packet.........")
        print ("Source IP: ", newpkt[IP].src)
        print ("Destination IP: ", newpkt[IP].dst)
 
        send(newpkt,verbose=0)
 
pkt = sniff(filter='icmp and arp ',prn=spoof_pkt)
##127.0.0.1
##172.17.0.1
##10.0.2.6
##10.9.0.1
