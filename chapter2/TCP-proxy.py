#!/usr/bin/python3
import sys
import socket
import threading

def server_loop(local_host, local_port, remote_host, remote_port, receive_first):


    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        server.bind((local_host, int(local_port)))
    except Exception as e:
        print("[-] Failed to listen on {}:{}".format(local_host, local_port))
        print("[-] Check for other listen port or socket or permissions {}".format(e))
        sys.exit(0)
    
    print("[*] Listening on {}:{}".format(local_host, local_port))
    server.listen(5)

    while True:
        client_socket, addr = server.accept()
        ## print out the local information
        print("[*] Recieve incoming connection from {}:{}".format(addr[0], addr[1]))

        ## start the thread to talk to the remote host
        proxy_thread = threading.Thread(target=proxy_handler,args=(client_socket,remote_host,remote_port,receive_first))
        proxy_thread.start()



def proxy_handler(client_socket, remote_host, remote_port, receive_first):

    ## connect to the remote host
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, remote_port))

    ## receive data from the remote end if necessary
    if receive_first:
        remote_buffer = receive_from(remote_socket)
        hexdump(remote_buffer)

        ## send it to our response handler
        remote_buffer = response_handler(remote_buffer)

        ## if we have data to send to our local client, send it
        if len(remote_buffer):
            print("[*] <=== Sending data {} bytes to localhost".format(len(remote_buffer)))
            client_socket.send(remote_buffer)
    

    ## lets loop and read from local
    ## send to remote, send to local
    while True:
        ## read from local host
        local_buffer = receive_from(client_socket)

        if len(local_buffer):
            print("[*] Received {} bytes from localhost".format(len(local_buffer)))
            hexdump(local_buffer)

            ## send it to our request handler
            local_buffer = request_handler(local_buffer)

            ## send off the data to the remote host
            remote_socket.send(local_buffer)
            print("[*] ==> sent to remote")
        
        remote_buffer = receive_from(remote_socket)
    

        if len(remote_buffer):
            print("[*] <== Received {} bytes from remote".format(len(remote_buffer)))
            hexdump(remote_buffer)

            ## send to our response handler
            remote_buffer = response_handler(remote_buffer)

            ## send the response to the local socket
            client_socket.send(remote_buffer)
    

    ## if no more data on either side, close the connections
        if not len(local_buffer) or not len(remote_buffer):
            client_socket.close()
            remote_socket.close()
            print("[*] No more data. Closing connections")
            break



def hexdump(src, length=8):
    result = []
    digits = 4 if isinstance(src, str()) else 2
    for i in range(0, len(src), length):
       s = src[i:i+length]
       hexa = b' '.join(["%0*X" % (digits, ord(x))  for x in s])
       text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.'  for x in s])
       result.append( b"%04X   %-*s   %s" % (i, length*(digits + 1), hexa, text) )
    return b'\n'.join(result)


def receive_from(connection):
    buffer = ""
    connection.timeout(2)

    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break
            buffer += data.decode('utf-8')
    except Exception as e:
        print(e)
        pass
    
    return buffer


## modify any request from the remote host
def request_handler(buffer):
    ## perform pack modifications
    return buffer


## modify any request from the localhost
def response_handler(buffer):
    ## perfom packet modifcations
    return buffer


def main():
    if len(sys.argv[1:]) != 5:
        print("[-] Usage: {} [localhost] [localport] [remotehost] [remoteport] [recieve_first]")
        print("[-] Example python3 TCP-proxy 127.0.0.1 9000 10.12.132.1 9000 True")
        sys.exit(0)
    

    ## setup local listen port
    local_host = sys.argv[1]
    local_port = sys.argv[2]

    ## setup remote target
    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])

    ## this tells our proxy to connect and receive data before seding to the remote host
    receive_first = sys.argv[5]

    if "True" in receive_first:
        receive_first = True
    else:
        receive_first = False
    
    ## now spin up our listening socket
    server_loop(local_host, local_port, remote_host, remote_port, receive_first)


if __name__ == "__main__":
    main()    