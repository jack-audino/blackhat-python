#!/usr/bin/env python3

import socket

target_host = '0.0.0.0'
target_port = 9999

# create socket object
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
'''
    - The AF_INET parameter means we are going to use a standard IPv4 address or hostname
    - The SOCK_STREAM parameter indicates that this will be a TCP client
'''

# connect to the client to the server
client.connect((target_host, target_port))

# send some data to the server
client.send(b'GET / HTTP/1.1\r\nHost: google.com\r\n\r\n')

# recieve some data from the server
response = client.recv(4096).decode()

print(response)