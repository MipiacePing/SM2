from random import randint
import math
from sm3 import sm3hash

# 实现加法，注意pow求逆的功能需要python3.8+
def ADD(x1,y1,x2,y2,a,p):
    if x1==x2 and y1==p-y2:
        return False
    if x1!=x2:
        lamda=((y2-y1)*pow(x2-x1,-1, p))%p
    else:
        lamda=(((3*x1*x1+a)%p)*pow(2*y1,-1, p))%p
    x3=(lamda*lamda-x1-x2)%p    # lamda 表达式
    y3=(lamda*(x1-x3)-y1)%p
    return x3,y3

# 求乘法，和传统ECC一样，本质还是调用加法
def Multiply(x,y,k,a,p):
    k=bin(k)[2:]
    qx,qy=x,y
    for i in range(1,len(k)):
        qx,qy=ADD(qx, qy, qx, qy, a, p)
        if k[i]=='1':
            qx,qy=ADD(qx, qy, x, y, a, p)
    return qx,qy

# KDF操作，是秘钥派生函数，
def KDF(z,klen):
    ct=1
    k=''
    for _ in range(math.ceil(klen/256)):
        k=k+sm3hash(hex(int(z+'{:032b}'.format(ct),2))[2:])
        ct=ct+1
    k='0'*((256-(len(bin(int(k,16))[2:])%256))%256)+bin(int(k,16))[2:]
    return k[:klen]

#parameters
p=0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
a=0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
b=0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
gx=0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
gy=0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
n=0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7

dB=randint(1,n-1)
xB,yB=Multiply(gx,gy,dB,a,p)


def encrypt(m:str):
    plen=len(hex(p)[2:])
    # 因为使用的字符串，所以转起来比较费劲
    m='0'*((4-(len(bin(int(m.encode().hex(),16))[2:])%4))%4)+bin(int(m.encode().hex(),16))[2:]
    klen=len(m)
    #对应SM2中间的循环操作
    while True:
        k=randint(1, n)
        while k==dB:
            k=randint(1, n)
        x2,y2=Multiply(xB, yB, k, a, p)
        x2,y2='{:0256b}'.format(x2),'{:0256b}'.format(y2)
        t=KDF(x2+y2, klen)
        if int(t,2)!=0:
            break
    x1,y1=Multiply(gx, gy, k, a, p)
    x1,y1=(plen-len(hex(x1)[2:]))*'0'+hex(x1)[2:],(plen-len(hex(y1)[2:]))*'0'+hex(y1)[2:]
    c1='04'+x1+y1
    c2=((klen//4)-len(hex(int(m,2)^int(t,2))[2:]))*'0'+hex(int(m,2)^int(t,2))[2:]
    c3=sm3hash(hex(int(x2+m+y2,2))[2:])
    return c1,c2,c3

# SM2解密
def decrypt(c1,c2,c3,a,b,p):
    c1=c1[2:]
    x1,y1=int(c1[:len(c1)//2],16),int(c1[len(c1)//2:],16)
    if pow(y1,2,p)!=(pow(x1,3,p)+a*x1+b)%p:
        return False
    x2,y2=Multiply(x1, y1, dB, a, p)
    x2,y2='{:0256b}'.format(x2),'{:0256b}'.format(y2)
    klen=len(c2)*4
    t=KDF(x2+y2, klen)
    if int(t,2)==0:
        return False
    m='0'*(klen-len(bin(int(c2,16)^int(t,2))[2:]))+bin(int(c2,16)^int(t,2))[2:]
    u=sm3hash(hex(int(x2+m+y2,2))[2:])
    if u!=c3:
        return False
    return hex(int(m,2))[2:]


if __name__ == "__main__":

    print("-----------------------------SM2 test-----------------------------\n")
    Msg = "Hello World"
    print("Msg:",Msg)
    c1,c2,c3=encrypt(Msg)
    c=(c1+c2+c3).upper()
    print('加密:')
    for i in range(len(c)):
        print(c[i*8:(i+1)*8],end=' ')
    print('解密:')
    m1=decrypt(c1, c2, c3, a, b, p)
    if m1:
        m1=str(bytes.fromhex(m1))
        m1='\n'.join(m1[2:-1].split('\\n'))
        print(m1)
        print(Msg==m1)
    else:
        print(False)
