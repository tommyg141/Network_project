from scapy.all import*
a =IP(dst = '8.8.8.8' , ttl =13)
b = ICMP(type=8)
p = a/b
send (p)
