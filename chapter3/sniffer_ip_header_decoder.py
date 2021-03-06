
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
        ## '@I' is unisigned int in native order. because c_ulong is 4 bytes in i386 and 8 in amd64
        self.src_address = socket.inet_ntoa(struct.pack("@I",self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("@I",self.dst))

    # human readble form
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            self.protocol = str(self.protocol_num)
            print(e)





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
        print("[*] Protocol {}:{} -> {} ".format(ip_header.protocol, ip_header.src_address, ip_header.dst_address))
except KeyboardInterrupt:
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
