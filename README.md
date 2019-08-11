# a DNS query agent for the people in PRC

## Install or Update
```
pip install -U git+https://github.com/lbp0200/prc-dns.git
```

## 用supervisor启动
配置文件

使用免费的PHP空间解析
```
[program:prc-dns]
command=/home/data/pyenv/2.7.14/bin/prcdns
autostart=true
autorestart=true
user=data
```

走SS通道解析，推荐，租个[搬瓦工](https://polr.liuboping.com/9zuU9)、[Vultr](https://polr.liuboping.com/PrgTf)、
[ChangeIP](https://polr.liuboping.com/changeip)、[PnzHost](https://polr.liuboping.com/pnzhost)，其实也花不了多少钱。
```
[program:prc-dns]
command=/home/data/pyenv/2.7.14/bin/prcdns --proxy 127.0.0.1:1080
autostart=true
autorestart=true
user=data
```

## 为什么不用OPENDNS
曾经用过pdnsd，设置上游为OPENDNS的TCP:208.67.222.222:443，发现`img.alicdn.com`解析到了
`69.192.12.15`香港，所以才做这个东西，用`https://dns.google.com/`查询DNS，根据`edns_client_subnet`
设置的公网IP参数，返回最近的IP。

## Wiki
- [参数说明](doc/parameter.md)
- [与其他DNS软件配合](doc/with_other.md)

## Thanks
copy some code from [Simple DNS server (UDP and TCP) in Python using dnslib.py](https://gist.github.com/andreif/6069838)
