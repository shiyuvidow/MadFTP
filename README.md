# MadFTP
simple ftp

Version: 2.7

MadFTP:

初始账户/密码：
wangwei/123
zhangsan/456

server端启动：
（MadFTPServer/bin）python ftp_server.py start

client端启动：
（MadFTPClient/bin）python ftp_client.py -s 127.0.0.1 -P 9999或者
python ftp_client.py -s 127.0.0.1 -P 9999 -u wangwei -p 123

参数说明：
-s: server ip
-P: server port
-u: username
-p: password

支持操作

1.用户登陆验证, 密码加密传输, 最大尝试错误数3次

2.不同用户登录家目录不同,每个用户只能登陆自己的家目录

3.查看当前路径pwd,不带参数

4.查看当前目录下文件ls,不带参数

5.创建目录mkdir

6.删除目录rm

7.进入目录cd

8.上传文件put,把client端的文件传到server端的当前目录下,不支持路径上传

$ cd /ect/profile

$ pwd

/etc/profile

$ ls

$ put xx.docx

$ ls

xx.docx

9.下载文件get,把server端的文件下载到client,支持路径下载

$ cd /a

$ get xx.txt

$ get /opt/xx.docx

10.上传/下载md5验证

$ put xx.docx --md5

11.上传/下载进度条显示

12.显示配额df,每个用户配额不一定相同，超过配额无法上传文件到server端

13.exit, 退出client端

14.断点续传