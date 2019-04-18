from pwn import *

cookie = ''
for i in range(61, 0, -1):
    try:
        p = remote('0', 9006)
        p.recvuntil('ID')
        p.sendline('-' * i)
        p.recvuntil('PW')
        p.sendline('')
        ciphertext = p.recvuntil(')')
        text = ciphertext[ciphertext.find('(')+1: ciphertext.find(')')][:128]
        p.close()
        for c in '_abcdefghijklmnopqrstuvwxyz1234567890,./;[]-=<>?:{}+|':
            p = remote('0', 9006)
            p.recvuntil('ID')
            p.sendline('-' * (i+2) + cookie + c)
            p.recvuntil('PW')
            p.sendline('')
            ciphertext = p.recvuntil(')')
            guess_text = ciphertext[ciphertext.find('(') + 1: ciphertext.find(')')][:128]
            p.close()
            if guess_text == text:
                cookie += c
                print ('cookie=' + cookie)
                break
    except:
        break
print cookie
