#!/usr/bin/python3
import socket
import os
import argparse

menu = argparse.ArgumentParser()
menu.add_argument('--host', help="host to listen ON", required=True)
parsed_menu =  menu.parse_args()

host = parsed_menu.host

## create a raw socket and bind to the public interface 
if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP


sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
sniffer.bind((host, 0))

## we wanted the IP addr include the capture
sniffer.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)

## windows use IOCTL
## set up promiscus mode
if os.name == 'nt':
    sniffer.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)

## read single packet
print(sniffer.recvfrom(65565))

## if we're windows, turn off promiscuos mode
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL,socket.RCVALL_OFF)
