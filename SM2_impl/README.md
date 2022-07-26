## 项目说明 --impl sm2 with RFC6979

✅Project: impl sm2 with RFC6979



## 运行说明

**开发环境**：Windows WSL（Ubuntu18.04）Python3

**默认执行环境**：Python3.8+ (必须要3.8，不然pow函数没有求逆功能)

**库依赖：**

```python
from random import randint
import math
```

**部分代码引用：**

[SM2](https://blog.csdn.net/qq_33439662/article/details/122590298?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522165909424616782246444181%2522%252C%2522scm%2522%253A%252220140713.130102334..%2522%257D&request_id=165909424616782246444181&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~top_positive~default-2-122590298-null-null.142^v35^pc_search_v2&utm_term=sm2%20python&spm=1018.2226.3001.4187)

**运行方式：**

- `$: python3 sm2.py`  



## SM2简介：

​		SM2为非对称加密，基于ECC。该算法已公开。由于该算法基于ECC，故其签名速度与秘钥生成速度都快于RSA。ECC 256位（SM2采用的就是ECC 256位的一种）安全强度比RSA 2048位高，但运算速度快于RSA。
​		旧标准的加密排序C1C2C3 新标准 C1C3C2，C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。



**基础参数：**

SM2的曲线方程为 $y^2 = x^3 + ax + by $
其中：

- a：0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
- b：0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
- p：0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF  
  
  私钥长度：32字节。

- 公钥长度：SM2非压缩公钥格式字节串长度为65字节，压缩格式长度为33字节，若公钥y坐标最后一位为0，则首字节为0x02，否则为0x03。非压缩格式公钥首字节为0x04。

- 签名长度：64字节。

**密钥生成：**

- 随机数$d\in [1,n-2],sk=d$

- G为基点，$pk = [d]G$

  

### **签名算法：**

**预处理1：**

输入

- ID：字符串，用户身份标识
- Q：SM2PublicKey，用户的公钥

输出

- Z：字节串，预处理1的输出$Z=SM3(ENTL∣∣ID∣∣a∣∣b∣∣x_G∣∣y_G∣∣x_A∣∣y_A)$
- ENTL为由2个字节标识的ID的比特长度，
- ID为用户身份标识。无特殊约定的情况下，用户身份标识ID的长度为16字节

**预处理2：**

使用Z值和待签名消息，通过SM3运算得到杂凑值H的过程

$H = SM3（Z||M）$

**签名：**

​	设待签名的消息为M，为了获取消息M的数字签名 ( r , s ) (r,s)(r,s)，作为签名者的用户A应实现以下运算步骤：

- 置  $\overline{M}=Z_A||M $


- 计算$e=H_v(\overline{M}) $,将 e的数据类型转化为整数；
- 用随机数发生器产生随机数$k\in[1,n-1]k∈[1,n−1] $；
- 计算椭圆曲线点$(x_1,y_1)=[k]G $
  将  $x_1 $ 的数据类型转化为整数；
- 计算$ r=(e+x_1) mod \ n$，若r=0 或 r + k = n则返回第3步；
- 计算 $s=((1+d_A)^{-1}\cdot (k-r \cdot d_A)) mod\ n$,若 s = 0 s=0s=0 则返回第3步；
- 将 r, s 转化为字节串。

**签名验证：**

为了检验收到的消息 M及其数字签名$( r , s )$，作为验证者的用户B应实现以下运算步骤：

 1. 检验 $r\in[1,n-1]r∈[1,n−1] $是否成立，若不成立则验证不通过；

 2. 检验 $s\in[1,n-1]s∈[1,n−1]$ 是否成立，若不成立则验证不通过；

 3. 置 $\overline{M}=Z_A||M $

 4. 计算$e=H_v(\overline{M})$将e的数据类型转化为整数；

 5. 将 r , s r,sr,s 的数据类型转化为整数，计算$t=(r+s) mod \ nt=(r+s)mod n $，若 t = 0,则验证不通过；

 6. 计算椭圆曲线点$ (x_1,y_1)=[s]G+[t]P_A$

 7. 将 $x_1$的数据类型转化为整数，计算$ R=(e+x_1) mod \ n$，检验 R = r是否成立，若成立则验证通过；否则验证不通过。

    

**签名验证原理：**

![verify](./picture/verify.png)

**SM2优点：**

SM2性能更优更安全：密码复杂度高、处理速度快、机器性能消耗更小

| 算法名称     | SM2                 | RSA                    |
| ------------ | ------------------- | ---------------------- |
| 算法结构     | 基本椭圆曲线（ECC） | 基于特殊的可逆模幂运算 |
| 计算复杂度   | 完全指数级          | 亚指数级               |
| 存储空间     | 192-256bit          | 2048-4096bit           |
| 秘钥生成速度 | 较RSA算法快百倍以上 | 慢                     |
| 解密加密速度 | 较快                | 一般                   |



## 运行截图：

![run](./picture/run.png)
