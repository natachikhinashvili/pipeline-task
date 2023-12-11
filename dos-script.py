from scapy.all import TCP, IP, sr1, conf

dstaddress = input('Destination address: ')
flag = input('Flag: ')
print(conf.route.route)

while True:
    p = sr1(IP(dst=dstaddress)/TCP(flags=flag))
    p.show()