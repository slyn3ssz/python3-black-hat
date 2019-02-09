
#!/usr/bin/python3

import socket
import os
import struct
from ctypes import *
import argparse

menu = argparse.ArgumentParser()
menu.add_argument("--host", required=True, help="Host to listen ON")
parsed_menu = menu.parse_args()

host = parsed_menu.host

## ip header
class IP(Structure):
    _fields_ = [
        ("ihl", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ushort),
        ("src", c_ulong),
        ("dst", c_ulong)
    ]


    def __new__(self, socket_buffer = None):
        return self.from_buffer_copy(socket_buffer)


    def __init__(self, socket_buffer=None):
        # map protocol constants to their names
        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}

    # human readble form
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            self.protocol = str(self.protocol_num)
            print(e)


## class icmp structure
class ICMP(Structure):
    _fields_ = [
        ("type", c_ubyte),
        ("code", c_ubyte),
        ("checksum", c_ushort),
        ("unused", c_short),
        ("next_hop_mtu", c_ushort)
    ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)


    def __init__(self, socket_buffer):
        pass





if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
sniffer.bind((host, 0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)


try:
    while True:
        # read in a packet
        raw_buffer = sniffer.recvfrom(65565)[0]
        ## create ip header from the first 20 bytes of the buffer
        ip_header = IP(raw_buffer[0:32])

        ## print out the protocol that was detected and the hosts
        print("[*] Protocol {}:{} -> {} ".format(ip_header.protocol, ip_header.src, ip_header.dst))

        if ip_header.protocol == "ICMP":
            ## calculate where our ICMP packet starts
            offset = ip_header.ihl * 4
            buf = raw_buffer[offset:offset + sizeof(ICMP)]
            ## create our ICMP structure 
            icmp_header = ICMP(buf)
            print("[+] ICMP --> Type: {} Code: {} ".format(icmp_header.type, icmp_header.code))   

except KeyboardInterrupt:
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
