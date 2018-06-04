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