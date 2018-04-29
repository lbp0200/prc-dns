# /usr/bin/env python2
# coding=utf-8
import sys
import datetime
import traceback
import threading
import socket
import re
import SocketServer
import logging
import argparse
from enum import Enum
from dnslib import *
import requests


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


DNS_SERVERS_IN_PRC = ['tcp:114.114.114.114',
                      'tcp:114.114.115.115',
                      'tcp:180.76.76.76',
                      'tcp:180.76.76.76',
                      'tcp:223.5.5.5',
                      'tcp:223.6.6.6', ]

server = 'https://prudent-travels.000webhostapp.com/dns.php?'
args = None


class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)


D = DomainName('baidu.com')

soa_record = SOA(
    mname=D.ns1,  # primary name server
    rname=D.andrei,  # email of the domain administrator
    times=(
        201307231,  # serial number
        60 * 60 * 1,  # refresh
        60 * 60 * 3,  # retry
        60 * 60 * 24,  # expire
        60 * 60 * 1,  # minimum
    )
)


def query_cn_domain(dns_req):
    proxy_request = DNSRecord(q=DNSQuestion(dns_req.q.qname, dns_req.q.qtype))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('', 0))
    s.sendall('Hello, world')
    data = s.recv(1024)
    s.close()
    print 'Received', repr(data)
    pass


def dns_response(data):
    dns_req = DNSRecord.parse(data)
    logging.debug('received DNS Request:')
    logging.debug(dns_req)

    qname = dns_req.q.qname
    qn = str(qname)
    qtype = dns_req.q.qtype
    qt = QTYPE[qtype]
    qc = dns_req.q.qclass
    logging.debug('%s %s', qn, qt)

    if qn.endswith('.cn.'):
        pass

    dns_reply = dns_req.reply()
    logging.debug("---- Reply:")
    logging.debug(dns_reply)
    logging.debug('reply pack------')

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
        # logging.debug('received request')
        try:
            data = self.get_data()
            # print len(data), data.encode('hex')  # repr(data).replace('\\x', '')[1:-1]
            self.send_data(dns_response(data))
        except Exception:
            traceback.print_exc(file=sys.stderr)


class TcpRequestHandler(MyBaseRequestHandler):
    pass


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
                        help='The DNS Server for cn domain,default random tcp:114.114.114,tcp:180.76.76.76 etc.',
                        default=None)
    args = parser.parse_args()

    if args.verbose:
        args.log = 'DEBUG'
    loglevel = args.log
    numeric_level = getattr(logging, str(loglevel).upper(), None)

    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % loglevel)
    logging.basicConfig(format='%(asctime)s %(message)s', level=numeric_level)

    if args.myip is None:
        resp = requests.get('http://ip.taobao.com/service/getIpInfo.php?ip=myip')
        myip_data = resp.json()
        args.myip = myip_data['data']['ip']
    else:
        from IPy import IP
        ip = IP(args.myip)
        if ip.iptype() == 'PRIVATE':
            raise ValueError('Invalid myip, it is a private IP, if you do not know what is it mean, leave it empty.')
    logging.debug('your public IP is %s', args.myip)
    return args


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
    tcp_server = ThreadedTCPServer((host, port), MyBaseRequestHandler)
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
    args = get_arg()
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
