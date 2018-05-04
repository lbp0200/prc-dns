# a DNS query agent for the people in PRC
之前用Python3.5写了一个[PRCDNS](https://github.com/lbp0200/PRCDNS)。
这个是用Python 2.7重写的，做了一些优化，支持IPV6，支持监听TCP、UDP，支持用国外PHP空间做代理。

## 改进
1. cn域名直接使用TCP协议`114.114.114.114:53`查询
2. 不再需要另外的代理，通过国外免费的PHP空间进行DNS查询的转发,将php文件夹中的`dns.php`
文件上传到你的PHP空间，并设置参数`--server`为`dns.php`的地址即可，
默认是[http://prudent-travels.000webhostapp.com/dns.php](http://prudent-travels.000webhostapp.com/dns.php)，免费流量100G每月。
国外的免费PHP空间还是很好找的。
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
usage: prc-dns [-h] [-v] [-l LISTEN] [-p PORT]
               [--log {CRITICAL,DEBUG,ERROR,INFO,WARNING}] [--tcp_udp TCP_UDP]
               [--myip MYIP] [--server SERVER] [--cn CN] [--proxy PROXY]

google dns proxy.

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         log out DEBUG 调试专用
  -l LISTEN, --listen LISTEN 
                        listening IP,default 0.0.0.0 
  -p PORT, --port PORT  listening Port,default 5333
  --log {CRITICAL,DEBUG,ERROR,INFO,WARNING}
                        Log Level,default ERROR 
  --tcp_udp TCP_UDP     DNS protocol, tcp udp or both 默认udp
  --myip MYIP           the Public IP of client, will get from taobao by
                        default 
                        软件启动后，去http://ip.taobao.com/service/getIpInfo.php?ip=myip
                        查询当前公网IP，用与优化CDN域名解析结果，返回最近的IP，默认空，设置后，
                        就不会去查询了，使用设置项。
  --server SERVER       The Server proxy DNS Request
                        部署在国外PHP空间的代理，请使用http，自带base64混淆，不要用https。  
  --cn CN               The DNS Server for cn domain,default random
                        tcp:114.114.114:53,udp:180.76.76.76:53 etc.
                        cn域名，直接用114查询，只有114支持TCP。
  --proxy PROXY         The socks5 proxy for to DNS over HTTPS, option, if it
                        is set, use https://dns.google.com/ to query, --server
                        will not use, demo user:pass@host:port or host:port
                        有自己的代理就更好了，不用国外PHP空间上的代理，直接访问https://dns.google.com/
```

还是没有DNS缓存，实在懒得弄，prc-dns前面放个dnsmasq或者pdnsd，效果更好。

## 为什么不用OPENDNS
曾经用过pdnsd，设置上游为OPENDNS的TCP:208.67.222.222:443，发现`img.alicdn.com`解析到了
`69.192.12.15`香港，所以才做这个东西，用`https://dns.google.com/`查询DNS，根据`edns_client_subnet`
设置的公网IP参数，返回最近的IP。

### pdnsd demo
```bash
global {
        perm_cache = 1024;
        cache_dir = "/var/cache/pdnsd";
        run_as = "pdnsd";
        server_ip = 0.0.0.0;
        server_port = 53;
        status_ctl = on;
        query_method = tcp_only; #只使用TCP协议查询上游，需要prc-dns也监听tcp
        min_ttl=15m;      
        max_ttl=1w;       
        timeout = 10;       
        par_queries = 1;
}
server {
	label = "prcdns";
	ip = 127.0.0.1;
	port = 5333; 
	proxy_only = on;
	timeout = 10;
	policy = included;
	uptest = none;
	exclude = .cn,.baidu.com,.91.com,.sohu.com,.sogou.com; # 特别常用的，直接国内
}
server {
        label= "114"; # 支持TCP，baidu、aliyun DNS 不支持TCP
        ip = 114.114.114.114,114.114.115.115;
        port = 53; 
        proxy_only = on; 
        timeout = 4;
        uptest = none;
        policy = included;
}
```
### dnsmasq demo
```bash
no-resolv #服务器还是使用原来的DNS，dnsmasq不读，避免部分无结果域名，再去resolv里的DNS服务器查询

server=/taobao.com/192.168.1.1
server=/cn/192.168.1.1
server=/#/127.0.0.1#5333
```
copy some code from [Simple DNS server (UDP and TCP) in Python using dnslib.py](https://gist.github.com/andreif/6069838)
