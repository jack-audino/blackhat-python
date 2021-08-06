#!/usr/bin/env python3

'''
How to use ***FOR TESTING AND EDUCATIONAL PURPOSES ONLY*** (instructions in the book weren't very clear):
    - create an ftp remote host on a different machine and make sure it's running
    - run this program on this machine with 'sudo ./proxy.py 127.0.0.1 21 [ip address of remote host with ftp server] 21 True'
    - on this machine in a different terminal, while TCP_proxy.py is running, use ftp to connect to localhost
    - go back to the terminal where TCP_proxy.py is running and you should see the traffic on the ftp server now
    - if no data is sent before the timeout, the connection will close
'''

import sys
import socket
import threading

# this is a pretty hex dumping function taken directly from the comments here (modified to work in python3):
# http://code.activestate.com/recipes/142812-hex-dumper/
# simply outputs the packet details with both their hexadecimal values and ASCII-printable characters
# this is useful for understanding unknown protocols, finding user credentials in plaintext protocols, and much more
def hexdump(src, length = 16):
    result = []
    digits = 4 if isinstance(src, str) else 2

    for i in range(0, len(src), length):
        s = src[i : i + length]
        hexa = b' '.join([b'%0*X' % (digits, ord(x)) for x in s])
        text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.'  for x in s])
        result.append(b'%04X   %-*s   %s' % (i, length * (digits + 1), hexa, text))

    print(b'\n'.join(result))

# this is used for both receiving local and remote data, and then we simply pass in the socket object to be used
# by default, there is a 2-second timeout set, whih might be aggressive if you are proxying traffic to other countries or
# over lossy networks (increase the timeout as necessary)
# the rest of the function simply handles receiving data until more data is detected on the other end of the connection
def receive_from(connection):
    buffer = b''

    # We set a 2 second timeout; depending on your target, this may need to be adjusted
    connection.settimeout(2)
    try:
        # keep reading this buffer until there's no more data, or we time out
        while True:
            data = connection.recv(4096)

            if not data:
                break
            
            buffer += data
    
    except TimeoutError:
        pass

    return buffer

# request_handler and response_handler can be useful for, example if plaintext user creds are being sent and you
# want to try to elevate privileges on an application by passing in 'admin' instead of say, 'justin'

# modify any requests destined for the remote host
def request_handler(buffer):
    # perform packet modifications
    return buffer

# modify any responses destined for the local host
def response_handler(buffer):
    # perform packet modifications
    return buffer

# contains the bulk of the logic for the proxy
def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    # connect to the remote host
    # ensure that we don't need to initiate a connection to the remote side and request data before going into the main loop
    # (some server daemons will expect us to do this first, FTP servers typically send a banner first)
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, remote_port))

    # receive data from the remote end if necessary
    if receive_first:
        # now we use our recieve_from function (that's used for both sides of communication)
        # it simply takes in a connected socket object and performs a receive
        remote_buffer = receive_from(remote_socket)

        # now we dump the contents of the packet so that we can inspect it for anything interesting 
        hexdump(remote_buffer)

        # send the output to our response_handler function
        # in response_handler, you can modify packet contents, perform fuzzing tasks, test for authentication issues, etc etc
        # the complimentary request_handler function that does the same for modifying outbound traffic as well **
        remote_buffer = response_handler(remote_buffer)

        # if we have data to send to our local client, send it
        if len(remote_buffer):
            print('[<==] Sending %d bytes to localhost.' % len(remote_buffer))
            client_socket.send(remote_buffer)

    # now lets loop and read from local, send to remote, send to local, rinse, wash, repeat
    while True:
        # read from local host
        local_buffer = receive_from(client_socket)

        if len(local_buffer):
            print('[==>] Recieved %d bytes from localhost.' % len(local_buffer))
            hexdump(local_buffer)

            # send it off to our request handler
            # ** this is the function referenced above
            local_buffer = request_handler(local_buffer)

            # send off the the data to the remote host
            remote_socket.send(local_buffer)
            print('[==>] Send to remote.')

        # receive back the response
        remote_buffer = receive_from(remote_socket)

        if len(remote_buffer):
            print('[<==] Recieved %d bytes from remote.' % len(remote_buffer))
            hexdump(remote_buffer)

            # send to our response handler
            remote_buffer = response_handler(remote_buffer)

            # send the response to the local socket
            client_socket.send(remote_buffer)

            print('[<==] Send to localhost.')

        # if no more data is on either side, close the connections
        # (send the received buffer to our local client)
        if not len(local_buffer) or not len(remote_buffer):
            client_socket.close()
            remote_socket.close()
            print('[*] No more data. Closing connections.')

            break

def server_loop(local_host, local_port, remote_host, remote_port, receive_first):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
            server.bind((local_host, local_port))
    except Exception as e:
            print('[!!] Failed to listen on %s:%d' % (local_host, local_port))
            print('[!!] Check for other listening sockets or correct permissions.')
            print(e)
            sys.exit(0)

    print('[*] Listening on %s:%d' % (local_host, local_port))

    server.listen(5)

    while True:
        client_socket, addr = server.accept()

        # print out local connection information
        print('[==>] Received incoming connection from %s:%d' % (addr[0], addr[1]))

        # start a thread to talk to the remote host and send the new connection to proxy_handler
        proxy_thread = threading.Thread(target = proxy_handler, args = (client_socket, remote_host, remote_port, receive_first))
        proxy_thread.start()

def main():
    # no fancy command-line parsing here
    if len(sys.argv[1:]) != 5:
        print('Usage: ./proxy.py [localhost] [localport] [remotehost] [remoteport] [receive_first]')
        print('Example: ./proxy.py 127.0.0.1 9000 10.12.132.1 9000 True')
        sys.exit(0)

    # set up local listening parameters from command-line arguments
    local_host = sys.argv[1]
    local_port = int(sys.argv[2])

    # set up remote target
    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])

    # this tells our proxy to connect and receive data before sending anything to the remote host
    receive_first = sys.argv[5]

    if "True" in receive_first:
        receive_first = True
    else:
        receive_first = False

    # now spin up our listening socket
    server_loop(local_host, local_port, remote_host, remote_port, receive_first)     

main()