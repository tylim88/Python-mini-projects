import asyncio


async def scan_port(ip, port, timeout):
    try:
        conn = asyncio.open_connection(ip, port)
        await asyncio.wait_for(conn, timeout=timeout)
        return port
    except:
        return None


async def scan_ports(ip, ports, timeout=1):
    open_ports = []
    tasks = [scan_port(ip, port, timeout) for port in ports]
    for result in await asyncio.gather(*tasks):
        if result:
            open_ports.append(result)
    return open_ports
