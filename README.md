# a DNS query agent for the people in PRC

## Install
```
pip install git+https://github.com/lbp0200/prc-dns.git
```

## 更新
```
pip install --upgrade git+https://github.com/lbp0200/prc-dns.git
```

## 用supervisor启动
配置文件
```
[program:prc-dns]
command=/home/data/pyenv/2.7.14/bin/prcdns
autostart=true
autorestart=true
user=data
```

## 为什么不用OPENDNS
曾经用过pdnsd，设置上游为OPENDNS的TCP:208.67.222.222:443，发现`img.alicdn.com`解析到了
`69.192.12.15`香港，所以才做这个东西，用`https://dns.google.com/`查询DNS，根据`edns_client_subnet`
设置的公网IP参数，返回最近的IP。

### pdnsd demo
```
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
	ip = 127.0.0.2;
	port = 5333; 
	proxy_only = on;
	timeout = 10;
	policy = included;
	uptest = none;
	exclude = .cn,.baidu.com,.91.com,.sohu.com,.sogou.com; # 特别常用的，直接国内
}
server {
        # 可以删除，备用
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
```
no-resolv # 服务器还是使用原来的DNS，dnsmasq不读，避免部分无结果域名，再去resolv里的DNS服务器查询

server=/taobao.com/192.168.1.1
server=/cn/192.168.1.1
server=/#/127.0.0.2#5333
```

copy some code from [Simple DNS server (UDP and TCP) in Python using dnslib.py](https://gist.github.com/andreif/6069838)
