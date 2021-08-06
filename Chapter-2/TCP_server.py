#!/usr/bin/env python3

'''
    - Note: TCP servers can be used when writing command shells or crafting a proxy
'''

import socket
import threading

# passing in the IP address and port we want the server to listen on
bind_ip = '0.0.0.0'
bind_port = 9999

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# listen with a maximum backlog of connections set to 5
server.bind((bind_ip, bind_port))

server.listen(5)

print('[*] Listening on %s:%d' % (bind_ip, bind_port))

# this is our client-handling thread
def handle_client(client_socket):
    
    # print out what the client sends
    request = client_socket.recv(4096)

    print('[*] Received: %s' % request.decode())

    # send back a packet
    client_socket.send(b'ACK!')

    client_socket.close()

# main loop where the server awaits an incoming connection
while True:
    '''
        - upon a client connecting:
            > we recieve the client socket and pass it into the 'client' variable
            > we recieve the remote connection details and pass it into the 'addr' variable
    '''
    client, addr = server.accept()
    print('[*] Accepted connection from %s:%d' % (addr[0], addr[1]))
   
    # spin up our client thread to handle incoming data, passing in the new 'client' object as an argument
    client_handler = threading.Thread(target = handle_client, args = (client, ))
    client_handler.start()