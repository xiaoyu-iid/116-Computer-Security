#! /usr/bin/env python
# Set log level to benefit from Scapy warnings
import logging
logging.getLogger("scapy").setLevel(1)
import base64
import imghdr
from scapy.all import *
import sys

pkt = rdpcap(sys.argv[1])

for p in pkts:
	if p.haslayer(Raw):
		imgstring = imgstring + p[RAW].load


imgdata = base64.b64decode(imgstring)
imgtype = imghdr.what(imgdata)


filename = 'output.'+ imgtype  
with open(filename, 'wb') as f:
    f.write(imgdata)
