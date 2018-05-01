# a DNS agent for the people in PRC

用Python 2.7重写了PRCDNS，定位于将软件放在局域网里面，特别是openwrt的路由器上。

## 改进
1. cn域名直接使用114查询
2. 不再需要另外的代理，通过国外免费的PHP空间进行DNS查询的转发

还是没有DNS缓存，实在懒得弄，prc-dns前面放个dnsmasq或者pdnsd，效果更好。

copy some code from [Simple DNS server (UDP and TCP) in Python using dnslib.py](https://gist.github.com/andreif/6069838)
