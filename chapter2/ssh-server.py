import paramiko
import socket
import threading
import sys


# GLOBAL VARS
YOUR_USER = ''
PASSWORD = ''


# using the key of paramiko files
host_keys = paramiko.RSAKey(filename='test_rsa.key')

class Server(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    
    def check_chanell_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    

    def check_auth_password(self, username, password):
        if (username == YOUR_USER) and (password == PASSWORD):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED
    

server = sys.argv[1]
ssh_port = sys.argv[2]


print(server,ssh_port)
print("sudo python3 {} <ip> <port>".format(sys.argv[0]))

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((server,int(ssh_port)))
    sock.listen(100)
    print("[+] Listening for connection...")
    client, addr = sock.accept()
except Exception as e:
    print("[-] Listen failed: {}".format(e))
    sys.exit(1)

print("[*] GOT CONNECTION")


try:
    bhSession = paramiko.Transport(client)
    bhSession.add_server_key(host_keys)
    server = Server()

    try:
        bhSession.start_server(server=server)
    except paramiko.SSHException as e:
        print("[-] SSH NEGOTIATION FAILED {}".format(e))

    chan = bhSession.accept(20)
    print("[*] Authenticated")
    print(chan.recv(1024))
    chan.send('Welcome to SSH SERVER')
    while True:
        try:
            command = input(">> Enter command: ".strip('\n'))
            if command != "exit":
                chan.send(command)
                print(chan.recv(1024))
            else:
                chan.send('exit')
                print("exiting")
                bhSession.close()
                raise Exception('exit')
        except KeyboardInterrupt as e:
            print("[*] Keyboard interrupt")
            bhSession.close()
except Exception as e:
    print("[-] Error Caught exception {}".format(e))
    try:
        bhSession.close()
    except Exception as e:
        print(e)
        pass
    sys.exit()