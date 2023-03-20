# MyRunas
Hook Windows自带的runas，用于自动输密码。

只适用于AD域环境。大概。

配合[还没上传的applist，预计23/03/22前上传](https://127.0.0.1)，可以做到AD域环境下，只要把安装包丢到指定共享目录，用户打开applist就可以直接点击安装。

applist就一win窗口程序，读取共享目录，根据共享文件自动绘制对应的按钮等控件。点击后调用myrunas运行对应程序。

真是安全又便利啊！（棒读

## 关于MyRunas
基于[MyRunas by YangFan](https://bbs.kanxue.com/thread-185411.htm)源码修改。修改以下功能：
- 将加密后的用户名作为密码传参给runasdll.dll。
- runasdll.dll将密码AES解密取得真密码。
- 用户名为administrator，写死在dll中
- AES密钥为.....，写死在dll中。

## 为何选择MyRunas
通常在AD域环境下，普通用户没有管理员权限。而lsrunase，PsExec等工具确实可以提权，但是无法使用当前用户环境变量。

这会导致通过这些方式提权安装某些文件的时候，安装路径会自动设置为Administrator的环境，导致后续无法正常使用。

而Windows自带的runas的/env参数，可以使用当前运行环境的环境变量。可惜runas不支持"|"管道符号等传递密码无法自动输入，/savecred保存凭据第一次需要输入密码不说，凭据直接保存在客户机还很危险。这意味着客户可以随时随地提权。

而MyRunas完美解决了这个问题。

在原版MyRunas中，作者直接读取MyRunas.ini中的密码，且密码明文保存。

故修改了部分逻辑，使其可以更安全的运用于生产环境。


## 使用方式
*建议自行编译修改。密钥以及用户名写死了，作为一个开源项目很危险。

如果您只是测试，请将bin目录下的

libcrypto-3.dll，MyRunas.exe，RunasDll.dll

复制到%systemroot

后续便可直接在cmd使用命令行操作。

或者可以新建个文件夹，将以上文件放进去，然后配置环境变量。

*推荐！因为这样可以通过AD域完成统一配置。

例：

`runas /env /user:administrator@microsoft.com cmd` 

修改为

`myrunas /env /user:aDMh7PBKZWnBbpuiWds3DQ--@microsoft.com cmd`

便可使用。


---


可以发现，以上命令与runas的命令似乎差不多。事实上也确实如此。

myrunas.exe用于接收命令行输入，将

`myrunas /env /user:aDMh7PBKZWnBbpuiWds3DQ--@microsoft.com cmd`

修改为

`runas /env /user:aDMh7PBKZWnBbpuiWds3DQ--@microsoft.com cmd`

传递给runas处理。

runas解析user为aDMh7PBKZWnBbpuiWds3DQ--。因为windows禁止用户名中有等于号，所以我们输密码的时候，需要将等于号转化为减号传递。

因为我们以及使用runasdll.dll去hook了runas，将这里的user截取下来，转为正确的密码后解密，就得到正确的密码了。

真正的user已经写死在dll里。具体实现请看dllmain.cpp中MyCreateProcessWithLogonW()函数。

## 修改方式
只需要修改用户名

`lpUsername = L"administrator@microsoft.com";//runas的用户名，以上已经获取了密码，所以这里固定写死。`

与修改密钥

`char key[32] = "iausohid$!@3e0wd#uijfonso$@#hdw"; // 定义密钥，固定长度。`

重新编译后就可以使用了。


## 使用环境
Visual Studio 2019

Win32 OpenSSL v3.1.0 [OpenSSL参考配置](https://www.cnblogs.com/Galesaur-wcy/p/15060819.html)

*exe安装版，请下载32位OpenSSL

[AES在线加解密](https://the-x.cn/cryptography/Aes.aspx)

## 免责声明
非专业程序员，自由式编码，看着头疼莫怪！请结合自身情况修改使用。

部分代码只能凑合用，比如密钥只能是31字节（实际32，c++中最后一位默认\0填充。）



## 收费项：

可定制编译（10rmb/次）：poi@yuzaoqian.club

觉得有价值直接打钱也可以XD
