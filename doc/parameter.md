之前用Python3.5写了一个[PRCDNS](https://github.com/lbp0200/PRCDNS)。

这个是用Python 2.7重写的，做了一些优化，支持IPV6，支持监听TCP、UDP，支持用国外PHP空间做代理。

## 改进
1. cn域名直接使用TCP协议`114.114.114.114:53`或者`240c::6666`查询
2. 不再需要另外的代理，通过国外免费的PHP空间进行DNS查询的转发,将php文件夹中的`dns.php`
文件上传到你的PHP空间，并设置参数`--server`为`dns.php`的地址即可，
默认是[http://prudent-travels.000webhostapp.com/dns.php](http://prudent-travels.000webhostapp.com/dns.php)，免费流量100G每月。
国外的免费PHP空间还是很好找的。

## 参数说明
```
usage: prc-dns [-h] [-v] [-H HOST] [-P PORT]
               [--log {CRITICAL,DEBUG,ERROR,INFO,WARNING}] [--tcp_udp TCP_UDP]
               [--myip MYIP] [--ip_version IP_VERSION] [--server SERVER]
               [--cn CN] [--cn6 CN6] [--proxy PROXY]

google dns proxy.

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         log out DEBUG
  -H HOST, --host HOST  listening IP,default 127.0.0.2
  -P PORT, --port PORT  listening Port,default 5333
  --log {CRITICAL,DEBUG,ERROR,INFO,WARNING}
                        Log Level,default ERROR
  --tcp_udp TCP_UDP     DNS protocol, tcp udp or both
  --myip MYIP           the Public IP v4 of client, will get it automatically
  软件启动后，去http://ip.taobao.com/service/getIpInfo.php?ip=myip
                          查询当前公网IP，用与优化CDN域名解析结果，返回最近的IP，默认空，设置后，
                          就不会去查询了，使用设置项。
  --ip_version IP_VERSION
                        The IP Version of NetWork, Enum(64=try ipv6
                        first,46=try ipv4 first),Default 46
  --server SERVER       The Server proxy DNS Request 部署在国外PHP空间的代理，请使用http，自带base64混淆，不要用https。 
  --cn CN               The DNS Server for cn domain,default is
                        tcp/114.114.114/53,set demo: udp/180.76.76.76/53
                        cn域名，直接用114查询，只有114支持TCP。
  --cn6 CN6             The DNS Server for cn domain,default is
                        (tcp/240c::6666/53),set demo:
                        udp/2a00:1450:4009:808::200e/53
  --proxy PROXY         The socks5 proxy for to DNS over HTTPS, option, if it
                        is set, use https://dns.google.com/ to query, --server
                        will not use, demo user:pass@host:port or host:port
                        有自己的代理就更好了，不用国外PHP空间上的代理，直接访问https://dns.google.com/
```

还是没有DNS缓存，实在懒得弄，prc-dns前面放个dnsmasq、pdnsd、Unbound（支持Windows），效果更好。
