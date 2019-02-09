
#!/usr/bin/python3

import socket
import os
import threading
import struct
from ctypes import *
import argparse
from netaddr import IPNetwork,IPAddress
import time

menu = argparse.ArgumentParser()
menu.add_argument("--host", required=True, help="Host to listen ON")
menu.add_argument("--subnet", required=True, help="Subnet to scan ex: 192.168.0.1/24")
parsed_menu = menu.parse_args()

host = parsed_menu.host
subnet = parsed_menu.subnet


print("{}:{}".format(host,subnet))
MAGIC_MESSAGE = "PYTHONRULES"


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
        ("src", c_uint32),
        ("dst", c_uint32)
    ]
    


    def __new__(self, socket_buffer = None):
        print(sizeof(self))
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



def udp_sender(subnet,magic_message):
    time.sleep(5)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for ip in IPNetwork(subnet):
        try:
            sender.sendto(MAGIC_MESSAGE.encode('utf-8'),("%s" % ip,65212))
        except Exception as e:
            pass
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



## start sending packets
t = threading.Thread(target=udp_sender,args=(subnet,MAGIC_MESSAGE))
t.start()


try:
    while True:
        # read in a packet
        raw_buffer = sniffer.recvfrom(65535)[0]
        ## create ip header from the first 20 bytes of the buffer
        ip_header = IP(raw_buffer)

        ## print out the protocol that was detected and the hosts
        print("[*] Protocol {}:{} -> {} ".format(ip_header.protocol, ip_header.src_address, ip_header.dst_address))

        if ip_header.protocol == "ICMP":
            ## calculate where our ICMP packet starts
            offset = ip_header.ihl * 4
            buf = raw_buffer[offset:offset + sizeof(ICMP)]
            ## create our ICMP structure 
            icmp_header = ICMP(buf)
            print("[+] ICMP --> Type: {} Code: {} ".format(icmp_header.type, icmp_header.code)) 
            if icmp_header.code == 3 and icmp_header.type == 3:
                if IPAddress(ip_header.src) in IPNetwork(subnet):
                    if raw_buffer[len(raw_buffer)-len(MAGIC_MESSAGE):] == MAGIC_MESSAGE:
                        print("[**] HOST UP {}".format(ip_header.src))  

except KeyboardInterrupt:
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
