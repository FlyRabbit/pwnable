from pwn import *
import os
pwn_ssh=ssh(host='pwnable.kr',user='col',password='guest',port=2222)
print (pwn_ssh.connected())
sh=pwn_ssh.process(argv=['collision','\xfc\x01\xf9\x39' * 5],executable='./col')
print (sh.recvall())