#!/usr/bin/env python3

# by using Paramiko and PyCrypto, we have access to SSH2

import threading
import paramiko
import subprocess
import os, pwd # using these in line 18 to get the user's name so the program is portable
import sys # added for command-line use

# this function is used to make a connection to an SSH server and runs a single command
def ssh_command(ip, user, passwd, command):
    client = paramiko.SSHClient()
    # Note: Paramiko supports authentication with keys instead of (or in addition to) password authentication
    # for real engagement, using SSH key authentication is strongly recommended 

    # this allows the client to also support using key files:
    #client.load_host_keys('/home/' + pwd.getpwuid(os.getuid())[0] + '/.ssh/known_hosts')

    # Since we're controlling both ends of this connection, we set the policy to accept the SSH key for the SSH server we're connecting to, and to make that connection
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username = user, password = passwd)
    ssh_session = client.get_transport().open_session()
    if ssh_session.active:
        # Assuming the connection is made, we run the command that we passed along in the call to the ssh_command() function
        ssh_session.exec_command(command)
        print(ssh_session.recv(1024))
    return


# added command line arguments since manually changing the code every time would be annoying
# however, since we always want to send 'id', I left it as an unchangeable argument
# the ip address of the server, username of the user running the SSH server on the target machine, and the password of the user in question
serverIp = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]

ssh_command(serverIp, username, password, 'id')