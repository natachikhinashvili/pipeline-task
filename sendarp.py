from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp
from scapy.all import sniff


eth=Ether()

eth.src="d0:21:f9:c5:74:0b"
eth.dst="ac:74:b1:12:d4:28"
arp = ARP()
arp.op = 1
arp.hwsrc = "d0:21:f9:c5:74:0b"
arp.hwdst = "ac:74:b1:12:d4:28"
arp.pdst="172.16.12.236"
arp.psrc="172.16.12.1"
responses = srp(eth/arp)
print(responses)