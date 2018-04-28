# /usr/bin/env python2
# coding=utf-8

import socket
import threading
import SocketServer
import logging
import argparse
from enum import Enum


class LogLevel(Enum):
    debug = 'DEBUG'
    info = 'INFO'
    warning = 'WARNING'
    error = 'ERROR'
    critical = 'CRITICAL'

    def __str__(self):
        return self.value


class ThreadedTCPRequestHandler(SocketServer.BaseRequestHandler):

    def handle(self):
        data = self.request.recv(1024)
        cur_thread = threading.current_thread()
        response = "{}: {}".format(cur_thread.name, data)
        self.request.sendall(response)


class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


class ThreadedUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):
    pass


def get_arg():
    """解析参数"""
    parser = argparse.ArgumentParser(prog='prc-dns', description='google dns proxy.')
    parser.add_argument('-v', '--verbose', help='log out DEBUG', action="store_true")
    parser.add_argument('--log', help='Log Level,default ERROR', type=LogLevel, choices=list(LogLevel), default='ERROR')
    parser.add_argument('-l', '--listen', help='listening IP,default 0.0.0.0', default='0.0.0.0')
    parser.add_argument('-p', '--port', help='listening Port,default 3535', default=3535)
    parser.add_argument('-r', '--proxy', help='Used For Query Google DNS,default direct', default=None)
    parser.add_argument('-ut', '--tcp_udp', help='DNS protocol, tcp udp or both', default='udp')

    return parser.parse_args()


def client(ip, port, message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    try:
        sock.sendall(message)
        response = sock.recv(1024)
        logging.info("Received: {}".format(response))
    finally:
        sock.close()


def main():
    args = get_arg()
    if args.verbose:
        args.log = 'DEBUG'
    loglevel = args.log
    numeric_level = getattr(logging, str(loglevel).upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % loglevel)
    logging.basicConfig(format='%(asctime)s %(message)s', level=numeric_level)
    
    # Port 0 means to select an arbitrary unused port
    HOST, PORT = "localhost", 0

    tcp_server = ThreadedTCPServer((HOST, PORT), ThreadedTCPRequestHandler)
    ip, port = tcp_server.server_address

    # Start a thread with the server -- that thread will then start one
    # more thread for each request
    tcp_server_thread = threading.Thread(target=tcp_server.serve_forever)
    # Exit the server thread when the main thread terminates
    tcp_server_thread.daemon = True
    tcp_server_thread.start()
    logging.info("Server loop running in thread:", tcp_server_thread.name)

    client(ip, port, "Hello World 1")
    client(ip, port, "Hello World 2")
    client(ip, port, "Hello World 3")

    tcp_server.shutdown()
    tcp_server.server_close()


if __name__ == "__main__":
    main()
