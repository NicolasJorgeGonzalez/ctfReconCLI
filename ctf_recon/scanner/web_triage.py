import asyncio
from typing import List, Optional, Set
import httpx

from ctf_recon.models import PortScanResult, WebTriageResult

COMMON_WEB_PORTS: Set[int] = {
    80, 443, 8000, 8008, 8080, 8443, 8888, 5000, 3000, 9000, 8081, 9090
}

KNOWN_NON_WEB_PORTS: Set[int] = {
    21, 22, 23, 25, 53, 110, 139, 143, 445, 3306, 5432, 6379, 27017
}

KEY_ROUTES: List[str] = ["/", "/robots.txt", "/.git/HEAD"]


def is_candidate_web_port(
    port: int,
    banner: Optional[str] = None,
    total_open_ports: Optional[int] = None
) -> bool:
    """Checks if a port is likely hosting a web service based on port number or banner."""
    if port in COMMON_WEB_PORTS:
        return True
    if banner:
        lower_banner = banner.lower()
        if any(proto in lower_banner for proto in ["ssh", "ftp", "smtp", "mysql", "postgresql", "redis"]):
            return False
        if any(keyword in lower_banner for keyword in ["http", "apache", "nginx", "html", "iis", "werkzeug", "uvicorn", "express"]):
            return True
    if port in KNOWN_NON_WEB_PORTS:
        return False
    if total_open_ports is not None and total_open_ports <= 10:
        return True
    return False


async def triage_web_endpoint(
    target: str,
    port: int,
    use_ssl: Optional[bool] = None,
    timeout: float = 1.5
) -> Optional[WebTriageResult]:
    """
    Triages a web service on a specific target and port.
    Inspects key routes, headers, redirects, and potential artifacts.
    """
    if use_ssl is None:
        scheme = "https" if port in {443, 8443} else "http"
    else:
        scheme = "https" if use_ssl else "http"

    base_url = f"{scheme}://{target}:{port}"
    redirects: List[str] = []
    findings: List[str] = []
    routes_checked: List[str] = []
    server_header: Optional[str] = None
    x_powered_by: Optional[str] = None
    root_status: Optional[int] = None

    client_kwargs = {
        "verify": False,
        "timeout": httpx.Timeout(timeout),
        "follow_redirects": True,
        "headers": {"User-Agent": "ctf-recon/0.1.0"}
    }

    try:
        async with httpx.AsyncClient(**client_kwargs) as client:
            # 1. Probe root /
            try:
                root_res = await client.get(f"{base_url}/")
                root_status = root_res.status_code
                routes_checked.append("/")

                # Track redirection chain
                for resp in root_res.history:
                    redirects.append(f"{resp.status_code} -> {resp.url}")

                server_header = root_res.headers.get("Server")
                x_powered_by = root_res.headers.get("X-Powered-By")

                if server_header:
                    findings.append(f"Server header: {server_header}")
                if x_powered_by:
                    findings.append(f"X-Powered-By header: {x_powered_by}")

                if root_res.text:
                    from ctf_recon.triage.flag_matcher import find_flags_in_text
                    for ff in find_flags_in_text(root_res.text, source=f"{base_url}/"):
                        findings.append(f"Flag found in body: {ff.flag_text}")

            except (httpx.RequestError, httpx.TimeoutException, OSError):
                # If HTTP failed on a non-standard port and we didn't try HTTPS yet, try HTTPS fallback
                if scheme == "http" and use_ssl is None:
                    return await triage_web_endpoint(target, port, use_ssl=True, timeout=timeout)
                return None

            # 2. Probe /robots.txt
            try:
                robots_res = await client.get(f"{base_url}/robots.txt")
                routes_checked.append("/robots.txt")
                if robots_res.status_code == 200 and robots_res.text:
                    from ctf_recon.triage.flag_matcher import find_flags_in_text
                    for ff in find_flags_in_text(robots_res.text, source=f"{base_url}/robots.txt"):
                        findings.append(f"Flag found in robots.txt: {ff.flag_text}")

                    disallowed = [
                        line.strip()
                        for line in robots_res.text.splitlines()
                        if line.lower().startswith("disallow:")
                    ]
                    if disallowed:
                        findings.append(f"/robots.txt found with entries: {', '.join(disallowed[:5])}")
                    else:
                        findings.append("/robots.txt accessible")
            except (httpx.RequestError, httpx.TimeoutException, OSError):
                pass

            # 3. Probe /.git/HEAD
            try:
                git_res = await client.get(f"{base_url}/.git/HEAD")
                routes_checked.append("/.git/HEAD")
                if git_res.status_code == 200 and "ref: refs/" in git_res.text:
                    findings.append("Exposed Git repository: /.git/HEAD returns valid ref")
            except (httpx.RequestError, httpx.TimeoutException, OSError):
                pass

        if root_status is not None:
            return WebTriageResult(
                url=base_url,
                status_code=root_status,
                server_header=server_header,
                x_powered_by=x_powered_by,
                redirects=redirects,
                findings=findings,
                routes_checked=routes_checked,
            )

    except Exception:
        return None

    return None


async def run_web_triage(
    target: str,
    open_ports: List[PortScanResult],
    timeout: float = 1.5,
    max_concurrency: int = 5
) -> List[WebTriageResult]:
    """
    Runs web triage on discovered open ports that appear to host web services.
    Uses asyncio.Semaphore to bound concurrency.
    """
    candidate_ports = [
        p.port for p in open_ports
        if is_candidate_web_port(p.port, p.banner, total_open_ports=len(open_ports))
    ]

    if not candidate_ports:
        return []

    semaphore = asyncio.Semaphore(max_concurrency)

    async def _bound_triage(port: int) -> Optional[WebTriageResult]:
        async with semaphore:
            return await triage_web_endpoint(target, port, timeout=timeout)

    tasks = [_bound_triage(port) for port in candidate_ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    triage_results: List[WebTriageResult] = []
    for res in results:
        if isinstance(res, WebTriageResult):
            triage_results.append(res)

    triage_results.sort(key=lambda x: x.url)
    return triage_results
