#!/usr/bin/env python3

'''
    - This will allow us to decode the ICMP messages that we see when using sniffer_ip_header_decode.py
        > More specifically, we are decoding the type, code and checksum fields of the ICMP header
            >> We are looking for a type value 3 and code value of 3 since these are what correspond to an ICMP
               message stating that a host is up, but there is no available port to talk to. Doing this will allow 
               us to see if there is a host at the IP address that we pinged.
'''

import socket
import os
import struct
from ctypes import *

# host to listen on (i.e. the ip address of the machine you're running this on)
host = '[host ip address]'

# our IP header
# We are defining a Python ctypes structure that maps the first 20 bytes of the received buffer into a friendly IP header
class IP(Structure):
    _fields_ = [
        ('ihl', c_ubyte, 4),
        ('version', c_ubyte, 4),
        ('tos', c_ubyte),
        ('len', c_ushort),
        ('id', c_ushort),
        ('offset', c_ushort),
        ('ttl', c_ubyte),
        ('protocol_num', c_ubyte),
        ('sum', c_ushort),
        ('src', c_uint32),
        ('dst', c_uint32)
    ]

    # this method simply takes in a raw buffer (in this case, what we receive from the network) and forms the structure from it
    # we run __new__ before __init__ so that way by the time __init__ is ran, the buffer has already been processed
    def __new__(cls, socket_buffer = None):
        return cls.from_buffer_copy(socket_buffer)

    # in this method, we are simply doing some housekeeping to make the output human-readable
    def __init__(self, socket_buffer = None):
        self.socket_buffer = socket_buffer

        # map protocol constants to their names
        self.protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}

        # human-readable IP addresses
        self.src_address = socket.inet_ntoa(struct.pack('@I', self.src))
        self.dst_address = socket.inet_ntoa(struct.pack('@I', self.dst))

        # human-readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except IndexError:
            self.protocol = str(self.protocol_num)

# our ICMP header
class ICMP(Structure):
    _fields_ = [
        ('type', c_ubyte),
        ('code', c_ubyte),
        ('checksum', c_ushort),
        ('unused', c_ushort),
        ('next_hop_mtu', c_ushort)
    ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass

# this should look familiar from the previous example (first_sniffer.py)
if os.name == 'nt':
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

sniffer.bind((host, 0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

if os.name == 'nt':
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

try:
    # now that we have a proper IP structure, we add logic to continually read in packets and parse their information
    while True:
        # first, we read in a single packet and pass them into a variable to be used later
        raw_buffer = sniffer.recvfrom(65565)[0]

        # we then initialize an IP header from the first 20 btyes of the buffer
        ip_header = IP(raw_buffer[:20])

        # print out the protocol that was detected, as well as the hosts (what we've captured)
        print('Protocol: %s %s -> %s' % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))

        # if it's ICMP, we want it
        if ip_header.protocol == 'ICMP':
            # calculate where our ICMP packet starts
            # more specifically, we calculate the offset in the raw packet where the ICMP body lives, then create the buffer

            # the length calculation of the buffer is based on the IP header 'ihl' field which indicates the number of 32-bit words in 4-byte chunks
            # by multiplying this field by 4, we know the size of the IP header, and by extension, when the next network layer (in this case, ICMP) begins
            offset = ip_header.ihl * 4
            buf = raw_buffer[offset:offset + sizeof(ICMP)]

            # create our ICMP structure
            icmp_header = ICMP(buf)

            print('ICMP -> Type: %d Code: %d' % (icmp_header.type, icmp_header.code))

# handle CTRL-C
except KeyboardInterrupt:
    # if we're using Windows, turn off promiscuous mode
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)