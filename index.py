# /usr/bin/env python2
# coding=utf-8
import sys
import datetime
import traceback
import threading
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


class DNS_CN(Enum):
    the_114 = '114.114.114.114'
    baidu = '180.76.76.76'
    aliyun = '223.5.5.5'

    def __str__(self):
        return self.value


server = 'https://prudent-travels.000webhostapp.com/dns.php?'


class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)


D = DomainName('baidu.com')
IP = '127.0.0.1'
TTL = 60 * 5
PORT = 5053

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
ns_records = [NS(D.ns1), NS(D.ns2)]
records = {
    D: [A(IP), AAAA((0,) * 16), MX(D.mail), soa_record] + ns_records,
    D.ns1: [A(IP)],  # MX and NS records must never point to a CNAME alias (RFC 2181 section 10.3)
    D.ns2: [A(IP)],
    D.mail: [A(IP)],
    D.andrei: [CNAME(D)],
}


def dns_response(data):
    dns_req = DNSRecord.parse(data)

    dns_req.reply()

    # reply = DNSReco?rd(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

    qname = dns_req.q.qname
    qn = str(qname)
    qtype = dns_req.q.qtype
    qt = QTYPE[qtype]

    if qn == D or qn.endswith('.' + D):

        for name, rrs in records.iteritems():
            if name == qn:
                for rdata in rrs:
                    rqt = rdata.__class__.__name__
                    if qt in ['*', rqt]:
                        reply.add_answer(RR(rname=qname, rtype=QTYPE[rqt], rclass=1, ttl=TTL, rdata=rdata))

        for rdata in ns_records:
            logging.debug(rdata)
            reply.add_ns(RR(rname=D, rtype=QTYPE.NS, rclass=1, ttl=TTL, rdata=rdata))

        reply.add_ns(RR(rname=D, rtype=QTYPE.SOA, rclass=1, ttl=TTL, rdata=soa_record))

    logging.debug("---- Reply:")
    logging.debug(reply)
    logging.debug('reply pack------')

    return reply.pack()


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
        except Exception :
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
    parser.add_argument('--cn', help='The DNS Server for cn domain', type=DNS_CN, default=DNS_CN.the_114)
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
