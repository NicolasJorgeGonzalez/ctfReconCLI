import asyncio
import pytest
from ctf_recon.models import PortScanResult, WebTriageResult
from ctf_recon.scanner.web_triage import (
    is_candidate_web_port,
    triage_web_endpoint,
    run_web_triage,
)


def test_is_candidate_web_port():
    assert is_candidate_web_port(80) is True
    assert is_candidate_web_port(443) is True
    assert is_candidate_web_port(8080) is True
    assert is_candidate_web_port(22) is False
    assert is_candidate_web_port(22, banner="SSH-2.0-OpenSSH") is False
    assert is_candidate_web_port(8888, banner=None) is True
    assert is_candidate_web_port(1337, banner="nginx/1.18.0") is True
    assert is_candidate_web_port(9999, banner="Apache/2.4.41 (Ubuntu)") is True
    assert is_candidate_web_port(9999, banner="Werkzeug/2.0.1 Python/3.9") is True


@pytest.mark.asyncio
async def test_triage_web_endpoint_success():
    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        request_line = await reader.readline()
        if not request_line:
            writer.close()
            await writer.wait_closed()
            return
        
        req_str = request_line.decode("utf-8", errors="ignore")
        # Consume rest of headers
        while True:
            line = await reader.readline()
            if line == b"\r\n" or line == b"\n" or not line:
                break

        if "GET / " in req_str:
            body = b"Welcome to Challenge"
            header = (
                b"HTTP/1.1 200 OK\r\n"
                b"Server: CustomServer/1.0\r\n"
                b"X-Powered-By: CustomFramework\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n"
            )
            writer.write(header + body)
        elif "GET /robots.txt" in req_str:
            body = b"User-agent: *\nDisallow: /secret_admin\n"
            header = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n"
            )
            writer.write(header + body)
        elif "GET /.git/HEAD" in req_str:
            body = b"ref: refs/heads/main\n"
            header = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n"
            )
            writer.write(header + body)
        else:
            writer.write(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n")

        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    async with server:
        res = await triage_web_endpoint("127.0.0.1", port, use_ssl=False, timeout=2.0)
        assert res is not None
        assert res.status_code == 200
        assert res.server_header == "CustomServer/1.0"
        assert res.x_powered_by == "CustomFramework"
        assert any("/robots.txt" in f for f in res.findings)
        assert any("Exposed Git repository" in f for f in res.findings)
        assert "/" in res.routes_checked
        assert "/robots.txt" in res.routes_checked
        assert "/.git/HEAD" in res.routes_checked


@pytest.mark.asyncio
async def test_triage_web_endpoint_connection_refused():
    # Attempting to scan a port that isn't listening should return None safely
    res = await triage_web_endpoint("127.0.0.1", 54321, use_ssl=False, timeout=0.5)
    assert res is None


@pytest.mark.asyncio
async def test_run_web_triage():
    # Only candidate web ports should be probed
    open_ports = [
        PortScanResult(port=22, banner="SSH-2.0-OpenSSH"),
        PortScanResult(port=54321, banner=None), # Not a web port
    ]
    results = await run_web_triage("127.0.0.1", open_ports, timeout=0.5)
    assert results == []
