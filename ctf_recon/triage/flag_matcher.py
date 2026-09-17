import base64
import re
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple, Union

from ctf_recon.models import FlagFinding, WebTriageResult

# Individual regex patterns for standard CTF flags with case-insensitive prefix
STANDARD_FLAG_PATTERNS: List[re.Pattern] = [
    re.compile(r"flag\{[^}]+\}", re.IGNORECASE),
    re.compile(r"htb\{[^}]+\}", re.IGNORECASE),
    re.compile(r"thm\{[^}]+\}", re.IGNORECASE),
    re.compile(r"picoctf\{[^}]+\}", re.IGNORECASE),
    re.compile(r"(?<!pico)ctf\{[^}]+\}", re.IGNORECASE),
]

# Combined regex pattern for fast single-pass matching of common flag formats
COMMON_FLAG_REGEX: re.Pattern = re.compile(
    r"(?:picoctf|(?<!pico)ctf|flag|htb|thm)\{[^}]+\}",
    re.IGNORECASE
)

# Regex matching potential Base64 candidates (alphanumeric, +, /, and optional 0-2 '=' padding)
BASE64_CANDIDATE_REGEX: re.Pattern = re.compile(
    r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{2,}={0,2})(?![A-Za-z0-9+/=])"
)


def extract_base64_candidates(text: str, min_length: int = 16) -> List[str]:
    """
    Extracts potential Base64 string candidates of at least `min_length` characters.
    """
    if not text or not isinstance(text, str):
        return []
    matches = BASE64_CANDIDATE_REGEX.findall(text)
    return [m for m in matches if len(m) >= min_length]


def safe_b64decode(candidate: str) -> Optional[bytes]:
    """
    Safely attempts to decode a candidate Base64 string into bytes.
    Handles padding normalization and avoids throwing exceptions.
    Returns bytes on successful decode, or None if invalid.
    """
    if not candidate or not isinstance(candidate, str):
        return None

    clean = candidate.strip()
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", clean):
        return None

    # Normalize padding: unpad first, then re-pad if needed
    clean_unpadded = clean.rstrip("=")
    rem = len(clean_unpadded) % 4
    if rem == 1:
        return None
    if rem != 0:
        clean = clean_unpadded + ("=" * (4 - rem))
    else:
        clean = clean_unpadded

    try:
        return base64.b64decode(clean, validate=True)
    except Exception:
        return None


def is_legible_text(text: str, min_len: int = 4) -> bool:
    """
    Checks if a decoded string is meaningful human-readable ASCII or UTF-8 text.
    Rejects strings that are purely whitespace, too short, or contain non-printable characters.
    """
    if not text or not isinstance(text, str):
        return False
    stripped = text.strip()
    if len(stripped) < min_len:
        return False
    return all(c.isprintable() or c in "\r\n\t" for c in stripped)


def _deduplicate_findings(findings: List[FlagFinding]) -> List[FlagFinding]:
    """Preserves insertion order while removing duplicates by (flag_text, source, format_type)."""
    seen: Set[Tuple[str, str, str]] = set()
    unique: List[FlagFinding] = []
    for f in findings:
        key = (f.flag_text, f.source, f.format_type)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def find_flags_in_text(
    text: str,
    source: str = "text",
    min_b64_len: int = 16,
    custom_patterns: Optional[List[Union[str, re.Pattern]]] = None,
) -> List[FlagFinding]:
    """
    Searches for CTF flags in the given text using standard flag patterns and
    by detecting and decoding Base64 blobs.

    Args:
        text: String content to inspect.
        source: Origin descriptor (e.g. 'text', 'banner', 'header:Cookie').
        min_b64_len: Minimum character length for Base64 blobs (default: 16).
        custom_patterns: Optional list of additional regex patterns to search for.

    Returns:
        List of unique FlagFinding objects.
    """
    findings: List[FlagFinding] = []
    if not text or not isinstance(text, str):
        return findings

    # Compile any custom patterns
    patterns = [COMMON_FLAG_REGEX]
    if custom_patterns:
        for cp in custom_patterns:
            if isinstance(cp, str):
                patterns.append(re.compile(cp, re.IGNORECASE))
            elif isinstance(cp, re.Pattern):
                patterns.append(cp)

    # 1. Search direct CTF flags via regex
    for pat in patterns:
        for match in pat.finditer(text):
            flag_str = match.group(0)
            findings.append(
                FlagFinding(
                    flag_text=flag_str,
                    source=source,
                    format_type="regex",
                )
            )

    # 2. Search for Base64 blobs
    candidates = extract_base64_candidates(text, min_length=min_b64_len)
    for candidate in candidates:
        raw_bytes = safe_b64decode(candidate)
        if raw_bytes is None:
            continue

        # Check if the decoded payload contains any CTF flags
        text_loose = raw_bytes.decode("utf-8", errors="ignore")
        b64_flag_matches: List[str] = []
        for pat in patterns:
            for match in pat.finditer(text_loose):
                b64_flag_matches.append(match.group(0))

        if b64_flag_matches:
            for flag_str in b64_flag_matches:
                findings.append(
                    FlagFinding(
                        flag_text=flag_str,
                        source=source,
                        format_type="base64_decoded",
                    )
                )
        else:
            # Check if decoded payload is legible UTF-8 text
            try:
                decoded_text = raw_bytes.decode("utf-8")
                if is_legible_text(decoded_text):
                    findings.append(
                        FlagFinding(
                            flag_text=decoded_text.strip(),
                            source=source,
                            format_type="base64_decoded",
                        )
                    )
            except UnicodeDecodeError:
                pass

    return _deduplicate_findings(findings)


def find_flags_in_headers(
    headers: Union[Mapping[str, Any], List[Tuple[Any, Any]], Dict[str, Any]],
    source_prefix: str = "header",
    min_b64_len: int = 16,
) -> List[FlagFinding]:
    """
    Searches for flags in HTTP headers (inspecting both header keys and header values).

    Args:
        headers: Mapping or list of key-value pairs representing HTTP headers.
        source_prefix: Prefix descriptor for source reporting.
        min_b64_len: Minimum character length for Base64 blobs.

    Returns:
        List of unique FlagFinding objects.
    """
    findings: List[FlagFinding] = []
    if not headers:
        return findings

    items: List[Tuple[Any, Any]] = []
    if isinstance(headers, list):
        items = headers
    elif hasattr(headers, "items"):
        try:
            items = list(headers.items())
        except Exception:
            return findings
    else:
        return findings

    for key, val in items:
        k_str = str(key)
        v_str = str(val)

        # Search header name / key
        findings.extend(
            find_flags_in_text(
                k_str,
                source=f"{source_prefix}:{k_str}",
                min_b64_len=min_b64_len,
            )
        )
        # Search header value
        findings.extend(
            find_flags_in_text(
                v_str,
                source=f"{source_prefix}:{k_str}",
                min_b64_len=min_b64_len,
            )
        )

    return _deduplicate_findings(findings)


def scan_target_for_flags(
    banners: Optional[List[str]] = None,
    web_results: Optional[List[WebTriageResult]] = None,
    min_b64_len: int = 16,
) -> List[FlagFinding]:
    """
    Orchestrates flag extraction across reconnaissance results:
    - Service banners from open ports
    - Web triage results (headers, findings, routes, redirects, bodies)

    Args:
        banners: List of banner strings extracted during port scanning.
        web_results: List of WebTriageResult objects from web triage.
        min_b64_len: Minimum character length for Base64 blobs.

    Returns:
        List of all discovered FlagFinding objects, deduplicated.
    """
    findings: List[FlagFinding] = []

    # 1. Inspect banners
    if banners:
        for banner in banners:
            if banner and isinstance(banner, str):
                findings.extend(
                    find_flags_in_text(banner, source="banner", min_b64_len=min_b64_len)
                )

    # 2. Inspect web results
    if web_results:
        for res in web_results:
            if not isinstance(res, WebTriageResult):
                continue

            url = res.url or "web"

            # Check headers
            headers_to_check: Dict[str, str] = {}
            if res.server_header:
                headers_to_check["Server"] = res.server_header
            if res.x_powered_by:
                headers_to_check["X-Powered-By"] = res.x_powered_by
            if hasattr(res, "headers") and isinstance(res.headers, dict):
                headers_to_check.update(res.headers)

            if headers_to_check:
                findings.extend(
                    find_flags_in_headers(
                        headers_to_check,
                        source_prefix=f"{url} header",
                        min_b64_len=min_b64_len,
                    )
                )

            # Check findings (e.g. /robots.txt or git HEAD entries)
            for item in res.findings or []:
                if item and isinstance(item, str):
                    findings.extend(
                        find_flags_in_text(
                            item,
                            source=f"web_finding:{url}",
                            min_b64_len=min_b64_len,
                        )
                    )

            # Check checked routes
            for route in res.routes_checked or []:
                if route and isinstance(route, str):
                    findings.extend(
                        find_flags_in_text(
                            route,
                            source=f"web_route:{url}",
                            min_b64_len=min_b64_len,
                        )
                    )

            # Check redirects
            for redir in res.redirects or []:
                if redir and isinstance(redir, str):
                    findings.extend(
                        find_flags_in_text(
                            redir,
                            source=f"web_redirect:{url}",
                            min_b64_len=min_b64_len,
                        )
                    )

            # Check body if available
            if hasattr(res, "body") and getattr(res, "body"):
                body_val = getattr(res, "body")
                if isinstance(body_val, str):
                    findings.extend(
                        find_flags_in_text(
                            body_val,
                            source=f"web_body:{url}",
                            min_b64_len=min_b64_len,
                        )
                    )

    return _deduplicate_findings(findings)
