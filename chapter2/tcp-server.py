#!/usr/bin/python3
import socket
import threading

binding_ip = "0.0.0.0"
port = 9999

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((binding_ip, port))
server.listen(5) # back log connections

print("[+] Listen ON {}:{}".format(binding_ip, port))


# client handling thread 
def handle_client(client_socket):
    # print what the client sends
    request = client_socket.recv(1024)

    print("[*] Request recivied {}".format(request))

    # send back a packet
    client_socket.send(b'ACK!')
    client_socket.close()

while True:
    client,addr = server.accept() # wait for connections
    print("[+] Accepted connection from: {}:{}".format(addr[0],addr[1]))

    # trigger the thread
    client_handler = threading.Thread(target=handle_client, args=(client,))
    client_handler.start()
