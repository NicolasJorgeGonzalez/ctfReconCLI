import asyncio
from typing import List, Optional

from ctf_recon.models import PortScanResult

TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
    139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587,
    631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900,
    2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101,
    5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081,
    8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157
]

def parse_ports(ports_str: Optional[str] = None) -> List[int]:
    if not ports_str or ports_str.strip().lower() == "top100":
        return sorted(TOP_100_PORTS)
        
    ports = set()
    parts = ports_str.split(',')
    
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            try:
                start_str, end_str = part.split('-', 1)
                start = int(start_str.strip())
                end = int(end_str.strip())
                if start <= end:
                    ports.update(range(start, end + 1))
                else:
                    ports.update(range(end, start + 1))
            except ValueError:
                pass
        else:
            try:
                port = int(part)
                ports.add(port)
            except ValueError:
                pass
                
    return sorted(list(ports))

async def scan_single_port(target: str, port: int, timeout: float = 1.5, semaphore: Optional[asyncio.Semaphore] = None) -> Optional[PortScanResult]:
    if semaphore:
        async with semaphore:
            return await _do_scan(target, port, timeout)
    else:
        return await _do_scan(target, port, timeout)

async def _do_scan(target: str, port: int, timeout: float) -> Optional[PortScanResult]:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port), timeout=timeout
        )
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError, asyncio.CancelledError):
        return None

    banner = None
    try:
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=0.2)
            if data:
                banner = data.decode('utf-8', errors='ignore').strip()
        except asyncio.TimeoutError:
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=0.2)
            if data:
                banner = data.decode('utf-8', errors='ignore').strip()
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    return PortScanResult(port=port, state="open", banner=banner)

async def scan_ports(target: str, ports: List[int], timeout: float = 1.5, max_concurrency: int = 100) -> List[PortScanResult]:
    semaphore = asyncio.Semaphore(max_concurrency)
    tasks = [scan_single_port(target, port, timeout, semaphore) for port in ports]
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    open_ports = []
    for r in results:
        if isinstance(r, PortScanResult):
            open_ports.append(r)
            
    open_ports.sort(key=lambda x: x.port)
    return open_ports
