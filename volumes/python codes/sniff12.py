from scapy.all import*
a = IP()
a.dst ='10.9.0.255'
a.src= '8.8.8.8'
b = ICMP()
b.type = 8
p =a/b
p.show()
send(p)
