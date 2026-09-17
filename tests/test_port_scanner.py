import asyncio
import pytest
from ctf_recon.scanner.port_scanner import parse_ports, scan_single_port, scan_ports, TOP_100_PORTS

def test_parse_ports_default():
    assert parse_ports() == sorted(TOP_100_PORTS)
    assert parse_ports("top100") == sorted(TOP_100_PORTS)
    assert parse_ports(" TOP100 ") == sorted(TOP_100_PORTS)

def test_parse_ports_comma():
    assert parse_ports("80, 443,8080") == [80, 443, 8080]

def test_parse_ports_range():
    assert parse_ports("1-5") == [1, 2, 3, 4, 5]
    assert parse_ports("5-1") == [1, 2, 3, 4, 5]

def test_parse_ports_mixed():
    assert parse_ports("80, 443, 8000-8002, 8001") == [80, 443, 8000, 8001, 8002]

def test_parse_ports_invalid():
    assert parse_ports("80, abc, 443, -1-") == [80, 443]

@pytest.mark.asyncio
async def test_scan_single_port_open():
    # Start a dummy server
    async def handle_client(reader, writer):
        writer.write(b"SSH-2.0-OpenSSH\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle_client, '127.0.0.1', 0)
    addr = server.sockets[0].getsockname()
    port = addr[1]

    async with server:
        result = await scan_single_port('127.0.0.1', port)
        assert result is not None
        assert result.port == port
        assert result.state == "open"
        assert result.banner == "SSH-2.0-OpenSSH"

@pytest.mark.asyncio
async def test_scan_single_port_closed():
    # Use a port that is likely closed (or bind and close)
    result = await scan_single_port('127.0.0.1', 65534, timeout=0.1)
    assert result is None

@pytest.mark.asyncio
async def test_scan_ports():
    async def handle_client(reader, writer):
        writer.close()
        await writer.wait_closed()

    server1 = await asyncio.start_server(handle_client, '127.0.0.1', 0)
    server2 = await asyncio.start_server(handle_client, '127.0.0.1', 0)
    
    port1 = server1.sockets[0].getsockname()[1]
    port2 = server2.sockets[0].getsockname()[1]

    async with server1, server2:
        results = await scan_ports('127.0.0.1', [port1, port2, 65534], timeout=0.2)
        assert len(results) == 2
        assert results[0].port in (port1, port2)
        assert results[1].port in (port1, port2)
        assert results[0].state == "open"
