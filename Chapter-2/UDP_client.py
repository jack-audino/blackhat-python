#!/usr/bin/env python3

import socket

target_host = '127.0.0.1'
target_port = 80

# create a socket object
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# the second parameter is now SOCK_DGRAM for UDP

# send some data
client.sendto(b'AAABBBCCC', (target_host, target_port))
'''
    - for UDP, only one method is needed to send data to a server (UDP is connectionless)
        > the first parameter is the data being sent
        > the second parameter is the host's ip and the port you want to send the data on
'''

# recieve some data
data, addr = client.recvfrom(4096)
# not only does recvfrom() return the data being sent back, but the remote host and port as well 

print(data)