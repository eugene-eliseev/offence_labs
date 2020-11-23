from scapy.all import *
from scapy.layers.inet import IP, TCP
from multiprocessing import Pool


def scan_port(src_ip, ip, port, interface):
    src_port = RandNum(1024, 65535)
    syn = TCP(sport=src_port, dport=port, flags="S")
    rst = TCP(sport=src_port, dport=port, flags="R")
    ip_data = IP(src=src_ip, dst=ip)
    p = sr1(ip_data / syn, timeout=2, verbose=False, iface=interface)

    if p:
        flags = p.getlayer(TCP).flags
        if flags == 0x12:
            send = sr1(ip_data / rst, timeout=2, verbose=False, iface=interface)
            return True
    return False


def get_ip_from_int(ip):
    data = []
    for i in range(4):
        part = (ip >> (i * 8)) & 255
        data.append(str(part))
    data.reverse()
    return '.'.join(data)


def scan_network(source, target, ports, interface, threads=50):
    ip, mask = target.split('/')
    first_address = 0
    for part in ip.split('.'):
        first_address = first_address << 8
        first_address = first_address | int(part)
    amount = ((256 ** 4 - 1) >> int(mask))
    bits = (~amount) & (256 ** 4 - 1)
    first_address = (first_address & bits) + 1
    print("Start scan from {} to {} for ports: {}".format(
        get_ip_from_int(first_address),
        get_ip_from_int(first_address + amount - 1),
        ','.join([str(i) for i in ports])
    ))
    scanning_data = []
    for i in range(amount):
        if (first_address + i) & 255 == 255:
            continue
        ip = get_ip_from_int(first_address + i)
        for port in ports:
            data = (source, ip, port, interface)
            if threads > 1:
                scanning_data.append(data)
            else:
                scan_mt(data)
    if threads > 1:
        pool = Pool(processes=threads)
        pool.map(scan_mt, scanning_data)
        pool.close()
        pool.join()
    print("Done")


def scan_mt(data):
    source, ip, port, interface = data
    if scan_port(source, ip, port, interface):
        print("{}:{} - opened".format(ip, port))
        return True
    return False


def main():
    # print(ifaces)
    target = "192.168.0.0/24"
    source = "192.168.0.163"
    ports = [80]
    threads = 1
    interface = "஫ ᥬ⢠ Realtek PCI GBE #3"
    scan_network(source, target, ports, interface, threads)


if __name__ == "__main__":
    main()
