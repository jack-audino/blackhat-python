#!/usr/bin/env python3

'''
    - this will implement the ipaddress module into sniffer_with_icmp.py to cover an entire subnet with our host discovery scan
'''

import socket
import os
import struct
import threading
from ipaddress import ip_address, ip_network
from ctypes import *

# host to listen on (i.e. the ip address of the machine you're running this on)
host = '[host ip address]'

# subnet to target
subnet = '[target subnet in slash notation]'

# a magic string that we'll check the incoming ICMP responses for
magic_message = 'PYTHONRULES!'

# this sprays out the UDP datagrams
# udp_sender() simply takes in a subnet that we have specified, iterates through all of the IP addresses in the subnet in question, and fires udp datagrams at them
def udp_sender(subnet, magic_message):
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for ip in ip_network(subnet).hosts():
        sender.sendto(magic_message.encode('utf-8'), (str(ip), 65212))

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

# start sending packets
# we spawn udp_sender() in a separate thread to ensure that we aren't interfering with our ability to sniff responses
t = threading.Thread(target = udp_sender, args = (subnet, magic_message))
t.start()

try:
    print('Running a net scan on:', subnet[:-3], 'depending on the size, this may take a while...')
    # now that we have a proper IP structure, we add logic to continually read in packets and parse their information
    while True:
        # first, we read in a single packet and pass them into a variable to be used later
        raw_buffer = sniffer.recvfrom(65565)[0]

        # we then initialize an IP header from the first 20 btyes of the buffer
        ip_header = IP(raw_buffer[:20])

        # (this is no longer needed so it's commented out)
        # print out the protocol that was detected, as well as the hosts (what we've captured)
        # print('Protocol: %s %s -> %s' % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))

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

            # (this is no longer needed so it's commented out)
            # print('ICMP -> Type: %d Code: %d' % (icmp_header.type, icmp_header.code))

            # now check for the TYPE 3 and CODE 3 which indicates a host is up but no port is available to talk to
            if icmp_header.code == 3 and icmp_header.type == 3:
                # check to make sure that we are receiveing the response that lands in our subnet
                if ip_address(ip_header.src_address) in ip_network(subnet):
                    # test for our magic message
                    # Note; you have to decode the sliced raw buffer since it was encoded upon sending, and if not decoded, it will still have b'' around it
                    if raw_buffer[len(raw_buffer) - len(magic_message):].decode() == magic_message:
                        print('Host Up: %s' % ip_header.src_address)

# handle CTRL-C
except KeyboardInterrupt:
    # if we're using Windows, turn off promiscuous mode
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
