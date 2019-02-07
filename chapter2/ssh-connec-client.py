#!/usr/bin/python3
import threading
import paramiko
import subprocess


def ssh_command(ip,user,passwd,command):
    client = paramiko.SSHClient()
    #client.load_host_keys('/home/$USER/.ssh/known_hosts')
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip,username=user,password=passwd)
    ssh_session = client.get_transport().open_session()
    if ssh_session.active:
        ssh_session.exec_command(command)
        print(ssh_session.recv(1024)) # read the banner
        try:
            cmd_output = subprocess.check_output(command, shell=True)
            ssh_session.send(cmd_output)
        except Exception as e:
            print("[-] Errro {}".format(e))
            ssh_session.send(str(e))
        client.close()
    return 

## run the 
ssh_command('127.0.0.1', 'user', 'password', 'id')
