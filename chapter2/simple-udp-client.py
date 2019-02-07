import socket


target = "127.0.0.1"
target_port = 80

# create a socket objt
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# send some data
client.sendto(b'AAAAABCDE', (target, target_port))

# recieve some data
data, addr = client.recvfrom(4096)


print("DATA {} \r\n ::: ADDR {} \n\n".format(data,addr))
