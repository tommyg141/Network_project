#!/usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
  pkt.show()

pkt = sniff(iface='br-e677e91290db', filter='tcp', prn=print_pkt)
