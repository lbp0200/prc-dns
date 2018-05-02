# a DNS query agent for the people in PRC

用Python 2.7重写了PRCDNS，定位于将软件放在局域网里面，特别是openwrt的路由器上。

## 改进
1. cn域名直接使用TCP协议`114.114.114.114:53`查询
2. 不再需要另外的代理，通过国外免费的PHP空间进行DNS查询的转发,将php文件夹中的`dns.php`文件上传到你的PHP空间，并设置参数`--server`为`dns.php`的地址即可，默认公共地址，但是公共地址可能超过流量限制，导致不稳定。
## 安装
```bash
pip install git+https://github.com/lbp0200/prc-dns.git
```
## 更新
```bash
pip install --upgrade git+https://github.com/lbp0200/prc-dns.git
```
## 启动
```bash
prcdns
```
## 参数说明
```bash
  -h, --help            show this help message and exit
  -v, --verbose         log out DEBUG
  -l LISTEN, --listen LISTEN
                        listening IP,default 0.0.0.0
  -p PORT, --port PORT  listening Port,default 5333
  --log {CRITICAL,DEBUG,ERROR,INFO,WARNING}
                        Log Level,default ERROR
  --tcp_udp TCP_UDP     DNS protocol, tcp udp or both, default udp
  --myip MYIP           the Public IP of client, will get from taobao by
                        default
  --server SERVER       The Server proxy DNS Request
  --cn CN               The DNS Server for cn domain,default random
                        tcp:114.114.114:53,udp:180.76.76.76:53 etc.

```

还是没有DNS缓存，实在懒得弄，prc-dns前面放个dnsmasq或者pdnsd，效果更好。

copy some code from [Simple DNS server (UDP and TCP) in Python using dnslib.py](https://gist.github.com/andreif/6069838)
