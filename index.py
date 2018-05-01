# /usr/bin/env python2
# coding=utf-8
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
import requests
import random
from IPy import IP


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


# 百度DNS多复制一次，保证随机取时，权重一样
DNS_SERVERS_IN_PRC = ['tcp:114.114.114.114:53',
                      'tcp:114.114.115.115:53',
                      'tcp:180.76.76.76:53',
                      'tcp:180.76.76.76:53',
                      'tcp:223.5.5.5:53',
                      'tcp:223.6.6.6:53', ]

server = 'https://prudent-travels.000webhostapp.com/dns.php'
args = None


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
    r = requests.get(args.server, {'name': qn, 'type': qt, 'edns_client_subnet': args.myip})
    logging.info('Query DNS over http, url: %s', r.url)
    logging.debug(r.text)
    return r.json()


def query_cn_domain(dns_req):
    proxy_request = DNSRecord(q=DNSQuestion(dns_req.q.qname, dns_req.q.qtype))
    dns_cn = random.choice(DNS_SERVERS_IN_PRC)
    (protocal, ip, port) = dns_cn.split(':')
    if protocal == 'tcp':
        data = query_over_tcp(proxy_request, ip, int(port))
    else:
        data = query_over_udp(proxy_request, ip, int(port))
    dns_result = DNSRecord.parse(data)
    logging.debug('cn domain query result is %s', dns_result)

    dns_reply = dns_req.reply()
    for r in dns_result.rr:
        dns_reply.add_answer(r)
    for a in dns_result.auth:
        dns_reply.add_auth(a)
    return dns_reply


def query_domain(qn, qt, qc):
    proxy_request = DNSRecord(q=DNSQuestion(qn, qt))
    dns_reply = proxy_request.reply()
    dns_result = query_over_http(qn, qt)
    if dns_result['Status'] == 0:
        for a in dns_result['Answer']:
            dns_reply.add_answer(RR(a['name'], a['type'], qc, a['TTL'], a['data']))
    elif dns_result['Status'] == 3:
        for a in dns_result['Authority']:
            dns_reply.add_auth(RR(a['name'], a['type'], qc, a['TTL'], a['data']))
    return dns_result


def dns_response(data):
    dns_req = DNSRecord.parse(data)
    logging.debug('Received DNS Request: %s', dns_req)

    qname = dns_req.q.qname
    qn = str(qname)
    qtype = dns_req.q.qtype
    qt = QTYPE[qtype]
    # qc = dns_req.q.qclass
    logging.info('Received DNS Request: %s %s', qn, qt)

    if qn.endswith('.cn.'):
        dns_reply = query_cn_domain(dns_req)
    else:
        dns_reply = query_domain(qn, qt, dns_req.q.qclass)

    logging.debug("DNS Reply: %s", dns_reply)

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
    parser.add_argument('-l', '--listen', help='listening IP,default 0.0.0.0', default='0.0.0.0')
    parser.add_argument('-p', '--port', help='listening Port,default 5333', default=5333)
    parser.add_argument('--log', help='Log Level,default ERROR', type=LogLevel, choices=list(LogLevel),
                        default=LogLevel.error)
    parser.add_argument('--tcp_udp', help='DNS protocol, tcp udp or both', type=Protocol, default=Protocol.udp)
    parser.add_argument('--myip', help='the Public IP of client, will get from taobao by default', default=None)
    parser.add_argument('--server', help='The Server proxy DNS Request', default=server)
    parser.add_argument('--cn',
                        help='The DNS Server for cn domain,default random tcp:114.114.114:53,tcp:180.76.76.76:53 etc.',
                        default=None)
    args = parser.parse_args()

    if args.verbose:
        args.log = 'DEBUG'
    loglevel = args.log
    numeric_level = getattr(logging, str(loglevel).upper(), None)

    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % loglevel)
    logging.basicConfig(format='%(asctime)s %(message)s', level=numeric_level)

    if args.cn is not None:
        (cn_proto, cn_ip, cn_port) = args.cn.split(':')
        if cn_proto not in ['tcp', 'udp']:
            raise ValueError('--cn protocol must be one of tcp or udp')
        cn_port = int(cn_port)
        if cn_port < 1 or cn_port > 65535:
            raise ValueError('--cn port error')
        IP(cn_ip)

    if args.server is None:
        args.server = server

    if args.myip is None:
        resp = requests.get('http://ip.taobao.com/service/getIpInfo.php?ip=myip')
        myip_data = resp.json()
        args.myip = myip_data['data']['ip']
    else:
        ip = IP(args.myip)
        if ip.iptype() == 'PRIVATE':
            raise ValueError('Invalid myip, it is a private IP, if you do not know what is it mean, leave it empty.')
    logging.debug('your public IP is %s', args.myip)


def client(ip, port, message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    try:
        sock.sendall(message)
        response = sock.recv(1024)
        logging.info("Received: {}".format(response))
    finally:
        sock.close()


def start_tcp_server(host, port):
    tcp_server = ThreadedTCPServer((host, port), TcpRequestHandler)
    ip, port = tcp_server.server_address

    tcp_server_thread = threading.Thread(target=tcp_server.serve_forever)
    tcp_server_thread.daemon = True
    tcp_server_thread.start()
    logging.info("DNS Server start running at tcp %s:%d", ip, port)
    return tcp_server


def start_udp_server(host, port):
    udp_server = ThreadedUDPServer((host, port), UdpRequestHandler)
    ip, port = udp_server.server_address

    udp_server_thread = threading.Thread(target=udp_server.serve_forever)
    udp_server_thread.daemon = True
    udp_server_thread.start()
    logging.info("DNS Server start running at udp %s:%d", ip, port)
    return udp_server


def main():
    get_arg()
    print(args)
    exit()
    # Port 0 means to select an arbitrary unused port
    HOST, PORT = args.listen, args.port
    servers = []
    if args.tcp_udp == Protocol.both:
        servers.append(start_tcp_server(HOST, PORT))
        servers.append(start_udp_server(HOST, PORT))
    elif args.tcp_udp == Protocol.tcp:
        servers.append(start_tcp_server(HOST, PORT))
    else:
        servers.append(start_udp_server(HOST, PORT))
    # client(ip, port, "Hello World 1")
    try:
        sys.stdin.read()
    except:
        pass
    finally:
        for s in servers:
            s.shutdown()
            s.server_close()


if __name__ == "__main__":
    main()
