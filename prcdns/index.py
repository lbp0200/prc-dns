# /usr/bin/env python2
# coding=utf-8

import os.path
import sys
import datetime
import traceback
import threading
# import socket
import SocketServer
import logging
import argparse
from enum import Enum
from dnslib import *
import random
import urllib
import json
from IPy import IP
from urlparse import urlparse
import re
import white_domain
from myrequests import requests_retry_session


class LogLevel(Enum):
    debug = 'DEBUG'
    info = 'INFO'
    warning = 'WARNING'
    error = 'ERROR'
    critical = 'CRITICAL'

    def __str__(self):
        return self.value


class Protocol(Enum):
    udp = 'udp'
    tcp = 'tcp'
    both = 'both'

    def __str__(self):
        return self.value


class IpVersion(Enum):
    ipv6_ipv4 = '64'
    ipv4_ipv6 = '46'

    def __str__(self):
        return self.value


white_domain_dict = white_domain.white_domain_dict
dns_servers_in_prc = None
dns4_servers_in_prc = ['tcp/114.114.114.114/53', 'tcp/114.114.115.115/53', ]
dns6_servers_in_prc = ['tcp/240c::6666/53', 'tcp/240c::6644/53', ]
server = 'http://prudent-travels.000webhostapp.com/dns.php'
ua_format = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.{0}.181 Safari/537.36'
args = None


def get_expire_datetime(ttl):
    return datetime.datetime.now() + datetime.timedelta(seconds=ttl if ttl > 0 else 365 * 24 * 60 * 60)


def get_inet_version(ip):
    if IP(ip).version() == 4:
        return socket.AF_INET
    else:
        return socket.AF_INET6


def query_over_tcp(proxy_request, ip, port):
    s = socket.socket(get_inet_version(ip), socket.SOCK_STREAM)
    s.connect((ip, port))
    q = proxy_request.pack()
    b_req = struct.pack(">H", q.__len__()) + q
    s.sendall(b_req)
    data = s.recv(1024)
    s.close()
    return data[2:]


def query_over_udp(proxy_request, ip, port):
    s = socket.socket(get_inet_version(ip), socket.SOCK_DGRAM)
    s.connect((ip, port))
    q = proxy_request.pack()
    s.sendall(q)
    data = s.recv(1024)
    s.close()
    return data


def query_over_http(qn, qt):
    start_time = time.time()
    myip = '43.250.236.4'
    if args.myip is not None:
        myip = args.myip
    try:
        if args.proxy is None:
            name = urllib.quote(base64.b64encode(qn))
            t = urllib.quote(base64.b64encode(qt))
            ecs = urllib.quote(base64.b64encode(myip))
            r = requests_retry_session().get(url=args.server,
                                             params={'name': name, 'type': t, 'edns_client_subnet': ecs},
                                             headers={'User-Agent': ua_format.format(random.randint(1, 9999))},
                                             timeout=(3.05, 27))
            resp = base64.b64decode(r.text)
        else:
            r = requests_retry_session().get(url=args.server,
                                             params={'name': qn, 'type': qt, 'edns_client_subnet': myip},
                                             headers={'User-Agent': ua_format.format(random.randint(1, 9999))},
                                             proxies={'http': args.proxy, 'https': args.proxy}, timeout=(3.05, 27))
            resp = r.text
        logging.info('Query DNS over http, url: %s', r.url)
        logging.debug('Query DNS over http, response: %s', resp)
        logging.debug("query_over_http executed --- %s seconds ---" % (time.time() - start_time))
        return json.loads(resp)
    except Exception as e:
        logging.warning("Query DNS over %s %s Error %s", args.server,
                        {'name': qn, 'type': qt, 'edns_client_subnet': args.myip},
                        e)
    logging.debug("query_over_http executed --- %s seconds ---" % (time.time() - start_time))


def query_cn_domain_by_domain(domain, cn_dns_list):
    proxy_request = DNSRecord(q=DNSQuestion(domain))
    dns_cn = random.choice(cn_dns_list)
    (protocal, ip, port) = dns_cn.split('/')
    logging.debug('use random cn DNS server %s %s:%s', protocal, ip, port)
    if protocal == 'tcp':
        data = query_over_tcp(proxy_request, ip, int(port))
    else:
        data = query_over_udp(proxy_request, ip, int(port))
    dns_result = DNSRecord.parse(data)
    logging.debug('cn domain query result is %s', dns_result)


def test_ip_version(domain='people.cn'):
    logging.info('test network is ipv6 or ipv4')
    global dns_servers_in_prc
    if args.ip_version == IpVersion.ipv4_ipv6:
        if args.cn:
            dns_servers_in_prc = args.cn
            args.ipv6 = False
        else:
            try:
                query_cn_domain_by_domain(domain, dns4_servers_in_prc)
                dns_servers_in_prc = dns4_servers_in_prc
                args.ipv6 = False
            except:
                dns_servers_in_prc = dns6_servers_in_prc
                args.ipv6 = True
    else:
        if args.cn6:
            dns_servers_in_prc = args.cn6
            args.ipv6 = True
        else:
            try:
                query_cn_domain_by_domain(domain, dns6_servers_in_prc)
                dns_servers_in_prc = dns6_servers_in_prc
                args.ipv6 = True
            except:
                dns_servers_in_prc = dns4_servers_in_prc
                args.ipv6 = False
    logging.info('cn dns upstream is %r', dns_servers_in_prc)


def query_cn_domain(dns_req):
    proxy_request = DNSRecord(q=DNSQuestion(dns_req.q.qname, dns_req.q.qtype))
    dns_cn = random.choice(dns_servers_in_prc)
    (protocal, ip, port) = dns_cn.split('/')
    logging.debug('use random cn DNS server %s %s:%s', protocal, ip, port)
    if protocal == 'tcp':
        data = query_over_tcp(proxy_request, ip, int(port))
    else:
        data = query_over_udp(proxy_request, ip, int(port))
    dns_result = DNSRecord.parse(data)
    logging.debug('cn domain query result is %s', dns_result)

    dns_reply = dns_req.reply()
    dns_reply.rr = dns_result.rr
    return dns_reply
    # for r in dns_result.rr:
    #     dns_reply.add_answer(r)
    # for a in dns_result.auth:
    #     dns_reply.add_auth(a)


def query_domain(dns_req):
    qname = dns_req.q.qname
    qn = str(qname)
    qt = dns_req.q.qtype
    qc = dns_req.q.qclass

    dns_reply = dns_req.reply()
    dns_result = query_over_http(qn, QTYPE[qt])
    if dns_result is None:
        dns_reply.header.rcode = 2
        return dns_reply
    else:
        if 'Answer' in dns_result:
            for a in dns_result['Answer']:
                dns_reply.add_answer(RR(a['name'], a['type'], qc, a['TTL'], globals()[QTYPE[a['type']]](a['data'])))
        if 'Authority' in dns_result:
            for a in dns_result['Authority']:
                dns_reply.add_auth(RR(a['name'], a['type'], qc, a['TTL'], globals()[QTYPE[a['type']]](a['data'])))
        return dns_reply


def get_root_domain(domain):
    fixed_domain = domain
    if not fixed_domain.endswith('.'):
        fixed_domain += '.'
    m = re.search('(.*\.)?([^.\n]+\.[^.\n]+\.)', fixed_domain)
    if m:
        groups = m.groups()
        if len(groups) > 1:
            return groups[1][:-1]
    return False


def is_domain_white_list(domain):
    if not domain.endswith('.cn.'):
        root_domain = get_root_domain(domain)
        if root_domain:
            if not root_domain in white_domain_dict:
                logging.debug("domain %s is not in white list", root_domain)
                return False
    logging.debug("domain %s is in white list", domain)
    return True


def is_server_cached():
    if args.server_key_4 in args.server_cache and args.server_cache[args.server_key_4]['rdata']:
        return True
    if args.server_key_6 in args.server_cache and args.server_cache[args.server_key_6]['rdata']:
        return True
    return False


def dns_response(data):
    try:
        dns_req = DNSRecord.parse(data)
        logging.debug('Received DNS Request: %s', dns_req)
    except:
        logging.warning('Recieved Unknown %r', data)
        return DNSRecord().reply(2).pack()

    qname = dns_req.q.qname
    qn = str(qname)
    qtype = dns_req.q.qtype
    qt = QTYPE[qtype]

    # get args.server from cache
    k = qn + '@' + qt
    if args.server_cache and k in args.server_cache and args.server_cache[k]['rdata']:
        dns_reply = dns_req.reply()
        dns_reply.rr = args.server_cache[k]['rdata']
        return dns_reply.pack()

    # 无代理，server 域名需要解析
    if args.proxy is None:
        logging.debug(args.server_cache)
        if not is_domain_white_list(qn) and args.server_cache and k not in args.server_cache and is_server_cached():
            logging.debug('use php server')
            dns_reply = query_domain(dns_req)
        else:
            dns_reply = query_cn_domain(dns_req)
            logging.debug('cache server result')
            if dns_reply.rr and k in args.server_cache:
                args.server_cache[k]['rdata'] = dns_reply.rr
                # server cname 也缓存
                for r in dns_reply.rr:
                    logging.debug('server result %r', r)
                    if r.rname != qname and QTYPE[r.rtype] in ['A', 'AAAA']:
                        logging.debug('cache server cname result, %s', r.rname)
                        cname_k = str(r.rname) + '@' + QTYPE[r.rtype]
                        args.server_cache[cname_k] = {'rdata': None}

    # 有代理，无需 server
    else:
        if not is_domain_white_list(qn):
            dns_reply = query_domain(dns_req)
        else:
            dns_reply = query_cn_domain(dns_req)

    logging.debug("response DNS reply %s", dns_reply)

    return dns_reply.pack()


class MyBaseRequestHandler(SocketServer.BaseRequestHandler):
    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        logging.debug("%s request %s (%s %s):" % (self.__class__.__name__[:3], now, self.client_address[0],
                                                  self.client_address[1]))
        try:
            data = self.get_data()
            self.send_data(dns_response(data))
        except Exception:
            traceback.print_exc(file=sys.stderr)


class TcpRequestHandler(MyBaseRequestHandler):
    def get_data(self):
        data = self.request.recv(1024).strip()
        sz = int(data[:2].encode('hex'), 16)
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = hex(len(data))[2:].zfill(4).decode('hex')
        return self.request.sendall(sz + data)


class UdpRequestHandler(MyBaseRequestHandler):
    def get_data(self):
        return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


class ThreadedUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):
    pass


def get_arg():
    """解析参数"""
    parser = argparse.ArgumentParser(prog='prc-dns', description='google dns proxy.')
    parser.add_argument('-v', '--verbose', help='log out DEBUG', action="store_true")
    parser.add_argument('-H', '--host', help='listening IP,default 127.0.0.2', default='127.0.0.2')
    parser.add_argument('-P', '--port', help='listening Port,default 5333', type=int, default=5333)
    parser.add_argument('--log', help='Log Level,default ERROR', type=LogLevel, choices=list(LogLevel),
                        default=LogLevel.error)
    parser.add_argument('--tcp_udp', help='DNS protocol, tcp udp or both', type=Protocol, default=Protocol.udp)
    parser.add_argument('--myip', help='the Public IP v4 of client, will get it automatically', default=None)

    parser.add_argument('--ip_version',
                        help='The IP Version of NetWork, Enum(64=try ipv6 first,46=try ipv4 first),'
                             'Default 46',
                        default=IpVersion.ipv4_ipv6)

    parser.add_argument('--server', help='The Server proxy DNS Request', default=server)
    parser.add_argument('--cn',
                        help='The DNS Server for cn domain,default is "tcp/114.114.114/53,tcp/114.115.115/53"'
                             'set demo: "udp/180.76.76.76/53,udp/223.5.5.5/53"',
                        default=None)
    parser.add_argument('--cn6',
                        help='The DNS Server for cn domain,default is "tcp/240c::6666/53,tcp/240c::6644/53",'
                             'set demo: "udp/2a00:1450:4009:808::200e/53,udp/::1/53"',
                        default=None)
    parser.add_argument('--proxy',
                        help='The socks5 proxy for to DNS over HTTPS, option, if it is set, '
                             'use https://dns.google.com/ to query, --server will not use, '
                             'demo user:pass@host:port or host:port',
                        default=None)
    parser.add_argument('--prc_domain',
                        help='file contains domains in prc ',
                        default='conf/prc-domain.txt')

    global args
    args = parser.parse_args()

    if args.verbose:
        args.log = 'DEBUG'
    log_level = args.log
    numeric_level = getattr(logging, str(log_level).upper(), None)

    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % log_level)
    logging.basicConfig(format='%(asctime)s %(message)s', level=numeric_level)

    if args.cn is not None:
        cn_ss = []
        cn_servers = args.cn.split(',')
        for cn_s in cn_servers:
            (cn_proto, cn_ip, cn_port) = cn_s.split('/')
            if cn_proto not in ['tcp', 'udp']:
                raise ValueError('--cn protocol must be one of tcp or udp')
            cn_port = int(cn_port)
            if cn_port < 1 or cn_port > 65535:
                raise ValueError('--cn port error')
            IP(cn_ip)
            cn_ss.append(cn_s)
        args.cn = cn_ss
    if args.cn6 is not None:
        cn6_ss = []
        cn6_servers = args.cn6.split(',')
        for cn6_s in cn6_servers:
            (cn6_proto, cn6_ip, cn6_port) = cn6_s.split('/')
            if cn6_proto not in ['tcp', 'udp']:
                raise ValueError('--cn protocol must be one of tcp or udp')
            cn6_port = int(cn6_port)
            if cn6_port < 1 or cn6_port > 65535:
                raise ValueError('--cn port error')
            IP(cn6_ip)
            cn6_ss.append(cn6_s)
        args.cn6 = cn6_ss

    if args.proxy is None:
        if args.server is None:
            args.server = server
        parsed_uri = urlparse(args.server)
        args.server_domain = parsed_uri.hostname
        args.server_key_4 = parsed_uri.hostname + '.@A'
        args.server_key_6 = parsed_uri.hostname + '.@AAAA'
        args.server_cache = {
            args.server_key_4: {'rdata': None, },
            args.server_key_6: {'rdata': None, },
        }
        # root_domain = get_root_domain(parsed_uri.hostname)
        # if root_domain:
        #     white_domain_dict[root_domain] = 1
        # else:
        #     raise Exception('Can not get Root Domain of ' + parsed_uri.hostname)
    else:
        args.server_cache = None
        args.proxy = 'socks5:{0}'.format(args.proxy)
        args.server = 'https://dns.google.com/resolve'

    # read prc_domain
    if os.path.exists(os.path.abspath(args.prc_domain)):
        with open(os.path.abspath(args.prc_domain)) as prc_domains:
            global white_domain_dict

            lines = prc_domains.readlines()
            dic = [l.strip() for l in lines if not l.strip().startswith('#')]
            for d in dic:
                if d and d not in white_domain_dict:
                    white_domain_dict[d] = 1

    if args.myip is not None:
        ip = IP(args.myip)
        if ip.iptype() == 'PRIVATE':
            raise ValueError('Invalid myip, it is a private IP, if you do not know what is it mean, leave it empty.')
        logging.info('your public IP v4 is %s', args.myip)


def start_tcp_server(host, port):
    tcp_server = ThreadedTCPServer((host, port), TcpRequestHandler)
    ip, port = tcp_server.server_address

    tcp_server_thread = threading.Thread(target=tcp_server.serve_forever)
    tcp_server_thread.daemon = True
    tcp_server_thread.start()
    print("DNS Server start running at tcp {}:{}".format(ip, port))
    return tcp_server


def start_udp_server(host, port, inet=socket.AF_INET):
    udp_server = ThreadedUDPServer((host, port), UdpRequestHandler, inet)
    ip, port = udp_server.server_address

    udp_server_thread = threading.Thread(target=udp_server.serve_forever)
    udp_server_thread.daemon = True
    udp_server_thread.start()
    print("DNS Server start running at udp {}:{}".format(ip, port))
    return udp_server


def main():
    get_arg()

    host, port = args.host, args.port
    servers = []
    if args.tcp_udp == Protocol.both:
        servers.append(start_tcp_server(host, port))
        servers.append(start_udp_server(host, port))
    elif args.tcp_udp == Protocol.tcp:
        servers.append(start_tcp_server(host, port))
    else:
        servers.append(start_udp_server(host, port))

    # 测试IPV6，选择上游cn DNS
    test_ip_version('www.people.cn')

    # Cache Server DNS Record
    if args.proxy is None:
        dns_response(DNSRecord(q=DNSQuestion(args.server_domain, 28 if args.ipv6 else 1)).pack())

    # DNS服务器启动后，开始解析自身依赖域名
    if args.myip is None:
        resp = requests_retry_session().get(args.server, timeout=(3.05, 27))
        myip_data = resp.json()
        args.myip = myip_data['origin']
        logging.info('your public IP is %s', args.myip)

    if args.server_cache:
        logging.debug('server_info is %r', args.server_cache)

    try:
        sys.stdin.read()
    except:
        pass
    finally:
        for s in servers:
            logging.info('Close socket server %s %s for exit', s.__class__.__name__[8:11], s.server_address)
            s.shutdown()
            s.server_close()


if __name__ == "__main__":
    main()
