import socket
import time


s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(('pwnable.kr',9007))
print (s.recv(4096))
time.sleep(3)
tot=0
index={}
string=''
for n in range(0,1000):
    string=string+str(n)+' '
    if n!=0:
        index[n]=index[n-1]+len(str(n-1))+1
    else:
        index[0]=0
#print (string[index[6]:index[118]])

while tot<100:
    st=s.recv(4096)
    N,C=st.split(' ')
    #print ("st:"+st)
    junk, N = N.split('=')
    junk, C = C.split('=')
    #print ("N and C:",N,C)
    l = 0
    r = int(N) - 1
    C=int(C)
    ctot=0
    while (l!=r):
        C=C-1
        mid = (l+r)/2
        num=''
        s.send (string[index[l]:index[mid+1]]+'\n')
        weight = s.recv(4096).strip()
        try:
            if (weight[len(weight)-1]=='9'):
                r=mid
            else:
                l = mid + 1
        except:
            print ('C :'+str(C)+" weight:" + weight+" num:"+num+' l and r',l,r)
            break


    while C>-1:
        s.send(str(l)+'\n')
        #print (C)
        C=C-1

    correct=s.recv(4096)
    if (len(correct)!=0 and correct[0]!='C'):
        correct=s.recv(4096)

    print ("Correct:"+correct)
    tot=tot+1


print (s.recv(4096))
