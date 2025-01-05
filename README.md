# Network-Sniffer

An assignment of mainly implementing a network sniffer using python, Django and Scapy.



## 立即运行

### 简单目录结构说明

```tree
.
├── client ------------- 客户端代码(网络流量需要被监听的客户端)
├── scripts ------------ 可运行脚本
├── server ------------- 服务端代码
├── README.md ---------- 此文档
├── requirements.txt --- python环境依赖
```

### 运行环境配置

操作系统：Windows或Linux。推荐使用Windows，因为开发和测试都在Windows上进行，Linux平台只经过少量测试。

1. python 3.11及以上

2. 为安装scapy库准备，参考[Download and Installation — Scapy 2.6.1 documentation](https://scapy.readthedocs.io/en/stable/installation.html#platform-specific-instructions)。要点：

   - Ubuntu: `sudo apt-get install libpcap-dev`
   - Windows: 安装[Npcap](https://nmap.org/npcap/)

   > ### Linux native[](https://scapy.readthedocs.io/en/stable/installation.html#linux-native)
   >
   > Scapy can run natively on Linux, without libpcap.
   >
   > - Install [Python 3.7+](http://www.python.org/).
   > - Install [libpcap](http://www.tcpdump.org/). (By default it will only be used to compile BPF filters)
   > - Make sure your kernel has Packet sockets selected (`CONFIG_PACKET`)
   > - If your kernel is < 2.6, make sure that Socket filtering is selected `CONFIG_FILTER`)
   >
   > ### Debian/Ubuntu/Fedora[](https://scapy.readthedocs.io/en/stable/installation.html#debian-ubuntu-fedora)
   >
   > Make sure libpcap is installed:
   >
   > - Debian/Ubuntu:
   >
   > ```
   > $ sudo apt-get install libpcap-dev
   > ```
   >
   > - Fedora:
   >
   > ```
   > $ yum install libpcap-devel
   > ```
   >
   > Then install Scapy via `pip` or `apt` (bundled under `python3-scapy`) All dependencies may be installed either via the platform-specific installer, or via PyPI. See [Optional Dependencies](https://scapy.readthedocs.io/en/stable/installation.html#optional-dependencies) for more information.
   >
   > ### Windows[](https://scapy.readthedocs.io/en/stable/installation.html#windows)
   >
   > You need to install Npcap in order to install Scapy on Windows (should also work with Winpcap, but unsupported nowadays):
   >
   > > - Download link: [Npcap](https://nmap.org/npcap/): [the latest version](https://nmap.org/npcap/#download)
   > >
   > > - - During installation:
   > >
   > >     we advise to turn **off** the `Winpcap compatibility mode`if you want to use your wifi card in monitor mode (if supported), make sure you enable the `802.11` option
   >
   > Once that is done, you can [continue with Scapy’s installation](https://scapy.readthedocs.io/en/stable/installation.html#latest-release).

3. 安装python环境，使用conda或virtualenv: `pip install -r requirements.txt`

   

### 运行脚本

见[scripts/README.md](.\\scripts\\README.md)



运行脚本后打开`127.0.0.1:8000`，脚本默认在8000端口提供服务
