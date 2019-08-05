from pwn import *
pwn_ssh=ssh(host='pwnable.kr',user='random',password='guest',port=2222)
print (pwn_ssh.connected())
sh=pwn_ssh.process(executable="./random")
sh.sendline('3039230856')
print(sh.recvall())


