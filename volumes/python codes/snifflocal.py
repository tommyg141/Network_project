#!/usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
  pkt.show()

pkt = sniff(iface='br-e677e91290db', filter='dst net 128.230.0.0/16', prn=print_pkt)
