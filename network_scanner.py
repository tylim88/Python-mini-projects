from scapy.all import ARP, Ether, srp
from port_scanner import scan_ports
import asyncio
import time
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from graphviz import Digraph


def visualize_network(devices):
    dot = Digraph(comment="Network Topology")
    for device in devices:
        dot.node(device["ip"], f"{device['ip']}\n{device['mac']}")
        for port, service in device["open_ports"]:
            dot.edge(device["ip"], f"{device['ip']}:{port}", label=service)
    dot.render("network_topology.gv", view=True)


def detect_os(ip):
    try:
        result = subprocess.run(["nmap", "-O", ip], capture_output=True, text=True)
        return result.stdout
    except FileNotFoundError as e:
        return f"Nmap not found: {e}"
    except Exception as e:
        return f"Error occurred: {e}"


def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except:
        return "Unknown service"


def scan_network(ip_range):
    # ARP = address protocol resolution
    arp = ARP(pdst=ip_range)  # send ARP request to IPs
    # Ether is ethernet
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # send to broadcast address
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]
    devices = []
    futures = []
    all_open_ports = {}
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    with ThreadPoolExecutor(max_workers=100) as executor:
        for index, (sent, received) in enumerate(result):
            all_open_ports[index] = scan_ports(received.psrc, range(20, 1025))
            future = executor.submit(detect_os, received.psrc)
            futures.append(future)
            devices.append(
                {
                    "ip": received.psrc,
                    "mac": received.hwsrc,
                }
            )
        for index, future in enumerate(futures):
            start_time = time.time()
            os_info = future.result()
            open_ports = loop.run_until_complete(all_open_ports[index])
            devices[index]["OS"] = os_info
            devices[index]["open_ports"] = [
                (port, get_service_name(port)) for port in open_ports
            ]
            devices[index]["in"] = f"{time.time() - start_time:.2f} seconds"
        loop.close()

    return devices


if __name__ == "__main__":
    ip_range = "192.168.1.1/24"
    print(ip_range)
    devices = scan_network(ip_range)
    # visualize_network(devices)
    for device in devices:
        print("===================================")
        print(
            f"IP: {device['ip']}, MAC: {device['mac']}, open ports: {device['open_ports']}, in: {device['in']}"
        )
        print("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        print(f"OS:{device['OS']}")
