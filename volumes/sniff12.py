from scapy.all import*
a = IP()
a.dst ='172.17.0.1'
a.src= '1.2.3.4'
b = ICMP()
p =a/b
p.show()
send(p,verbose=0)
