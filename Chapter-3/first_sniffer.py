#!/usr/bin/env python3

'''
    - the main goal of this sniffer is to perform UDP-based host discovery on a target network
    - we can determine if a host at a specifc IP address is active or not based on whether or not we recieve an ICMP packet after sending a
      UDP datagram, if we don't recieve a packet, then we can assume that there is no host at the specific IP address
'''
import socket
import os

# host to listen on (i.e. the ip address of the machine you're running this on)
host = '[host ip address]'

# create a raw socket and bind it to the public interface
# we start by constructing our socket object with the parameters necessary for sniffing packets on our network interface
if os.name == 'nt':
    # if we're on Windows, we're allowed to sniff all incoming packets regardless of protocol
    socket_protocol = socket.IPPROTO_IP
else:
    # if we're on Linux, we have to specify that we are using the ICMP protocol
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

sniffer.bind((host, 0))

# we want the IP headers included in the capture, so we set a socket option that includes IP headers in our captured packets
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# if we're on Windows, we need to send an IOCTL to set up promiscuous mode
# Promiscuous mode requires administrative mode on Windows and root on Linux
# Note: promiscuous mode allows us to sniff all packets that the network card sees, even those not destined for your specific host
if os.name == 'nt':
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# read in a single packet
# we are simply printing out the entire raw packet with no packet decoding
# this is just to test to make sure that we have the core of our sniffing code working
print(sniffer.recvfrom(65535))

# if we're on Windows, turn off promiscuous mode
if os.name == 'nt':
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
