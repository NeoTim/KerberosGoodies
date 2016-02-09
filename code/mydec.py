from pyasn1.codec.der import decoder

data = open("data").read()

out = decoder.decode(data)

print out

import socket
import dpkt
import sys

pcapReader = dpkt.pcap.Reader(file(sys.argv[1], "rb"))
for ts, data in pcapReader:
    ether = dpkt.ethernet.Ethernet(data)
    if ether.type != dpkt.ethernet.ETH_TYPE_IP:
        continue
    ip = ether.data
    src = socket.inet_ntoa(ip.src)
    dst = socket.inet_ntoa(ip.dst)
    print "%s -> %s" % (src, dst)

    ip = dpkt.ip.IP(data[14:])
    if(type(ip) != dpkt.ip.IP):
        continue
    tcp = ip.data
    if(type(tcp) != dpkt.tcp.TCP):
        continue
    print "hello"
