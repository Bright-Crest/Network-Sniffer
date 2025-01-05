# 运行程序

## 不同平台说明

推荐使用Windows，因为开发和测试都在Windows上进行，Linux平台只经过少量测试。



Windows：

1. 打开`cmd.exe`（python包scapy部分功能可能需要管理员权限）
2. 激活python环境
3. 运行后缀名为`bat`的脚本



Linux：

1. 打开`shell`
2. 激活python环境
3. 添加`sh`脚本运行权限 `chmod u+x setup.sh run_all.sh run_server.sh run_client.sh`
4. 运行后缀名为`sh`的脚本（python包scapy部分功能可能需要管理员权限）



## Simple: 立即运行

Windows:

```cmd
> setup.bat
> run_all.bat
```

（执行后弹出两个新的cmd，分别是server和client）



Linux:

```bash
$ setup.sh
$ run_all.sh
```



注：setup只需要运行一次



## 脚本说明

### setup

server初始化

只需要运行一次

### run_server

服务器

### run_client

客户端：网络流量需要被监听的计算机。服务器网站的浏览者是不需要运行的。

### run_all

调用run_server和run_client，并行运行，用于在一台计算机上同时运行server和client，方便测试

