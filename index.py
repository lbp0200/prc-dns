# /usr/bin/env python2
# coding=utf-8

import socket
import threading
import SocketServer
import logging


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


def client(ip, port, message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    try:
        sock.sendall(message)
        response = sock.recv(1024)
        logging.info("Received: {}".format(response))
    finally:
        sock.close()


if __name__ == "__main__":
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
