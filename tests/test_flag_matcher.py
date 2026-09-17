import base64
import os
import pytest

from ctf_recon.models import FlagFinding, WebTriageResult
from ctf_recon.triage.flag_matcher import (
    COMMON_FLAG_REGEX,
    STANDARD_FLAG_PATTERNS,
    safe_b64decode,
    is_legible_text,
    extract_base64_candidates,
    find_flags_in_text,
    find_flags_in_headers,
    scan_target_for_flags,
)


class TestFlagMatcherDirect:
    """Unit tests for direct regex CTF flag detection."""

    @pytest.mark.parametrize(
        "sample,expected_flag",
        [
            ("Here is the flag: flag{simple_user_flag_123}", "flag{simple_user_flag_123}"),
            ("Secret: FLAG{UPPERCASE_FLAG_456}", "FLAG{UPPERCASE_FLAG_456}"),
            ("Found Flag{Mixed_Case_Flag_789} in text", "Flag{Mixed_Case_Flag_789}"),
            ("Root token: HTB{hack_the_box_root_pwn}", "HTB{hack_the_box_root_pwn}"),
            ("user token: htb{htb_lowercase_flag}", "htb{htb_lowercase_flag}"),
            ("Room cleared: THM{try_hack_me_box_pwned}", "THM{try_hack_me_box_pwned}"),
            ("room token: thm{thm_lowercase_flag}", "thm{thm_lowercase_flag}"),
            ("Solv: picoCTF{overflow_payload_success}", "picoCTF{overflow_payload_success}"),
            ("solv: picoctf{pico_lowercase_flag}", "picoctf{pico_lowercase_flag}"),
            ("Chall: CTF{generic_jeopardy_flag}", "CTF{generic_jeopardy_flag}"),
            ("chall: ctf{generic_lowercase_flag}", "ctf{generic_lowercase_flag}"),
            ("FaMAF CTF: FaMAF{br0k3n_4cc3ss_c0ntr0l_ch3ck_th3_0wn3r}", "FaMAF{br0k3n_4cc3ss_c0ntr0l_ch3ck_th3_0wn3r}"),
            ("lowercase: famaf{famaf_lowercase_sample}", "famaf{famaf_lowercase_sample}"),
        ],
    )
    def test_flag_formats_detection(self, sample: str, expected_flag: str):
        findings = find_flags_in_text(sample, source="test")
        assert len(findings) >= 1
        flags = [f.flag_text for f in findings]
        assert expected_flag in flags
        matching_finding = next(f for f in findings if f.flag_text == expected_flag)
        assert matching_finding.format_type == "regex"
        assert matching_finding.source == "test"

    def test_picoctf_ctf_no_duplicate_collision(self):
        """picoCTF{...} should not be falsely split into both picoCTF{...} and CTF{...}."""
        text = "Congrats: picoCTF{clean_match_only}"
        findings = find_flags_in_text(text)
        flags = [f.flag_text for f in findings]
        assert "picoCTF{clean_match_only}" in flags
        assert "CTF{clean_match_only}" not in flags

    def test_multiple_flags_in_text(self):
        text = (
            "Service output: flag{flag_one} and also HTB{flag_two}, "
            "finally THM{flag_three}."
        )
        findings = find_flags_in_text(text)
        assert len(findings) == 3
        flags = {f.flag_text for f in findings}
        assert flags == {"flag{flag_one}", "HTB{flag_two}", "THM{flag_three}"}

    def test_html_and_code_embedded_flags(self):
        html = """
        <!DOCTYPE html>
        <html>
            <body>
                <!-- Hidden admin note: flag{comment_flag_123} -->
                <script>
                    const token = "HTB{javascript_variable_flag}";
                </script>
                <p>Welcome to CTF</p>
            </body>
        </html>
        """
        findings = find_flags_in_text(html, source="web_body")
        flags = {f.flag_text for f in findings}
        assert "flag{comment_flag_123}" in flags
        assert "HTB{javascript_variable_flag}" in flags
        for f in findings:
            assert f.source == "web_body"


class TestBase64Decoding:
    """Unit tests for Base64 blob extraction and safe decoding."""

    def test_safe_b64decode_valid_padded(self):
        b64 = base64.b64encode(b"flag{secret_in_b64}").decode("ascii")
        res = safe_b64decode(b64)
        assert res == b"flag{secret_in_b64}"

    def test_safe_b64decode_unpadded(self):
        b64 = base64.b64encode(b"THM{unpadded_flag}").decode("ascii").rstrip("=")
        res = safe_b64decode(b64)
        assert res == b"THM{unpadded_flag}"

    def test_safe_b64decode_corrupt(self):
        assert safe_b64decode("invalid!!!chars") is None
        assert safe_b64decode("abc===") is None
        assert safe_b64decode("") is None
        assert safe_b64decode(None) is None

    def test_is_legible_text(self):
        assert is_legible_text("admin:password123") is True
        assert is_legible_text("flag{hello}") is True
        assert is_legible_text("Multi\nLine\tText") is True
        assert is_legible_text("") is False
        assert is_legible_text("   ") is False
        assert is_legible_text("hi") is False  # too short (< 4 chars)
        assert is_legible_text("\x00\x01\x02\x03\x04") is False
        assert is_legible_text("Hello\x00World") is False

    def test_b64_encoded_flags_in_text(self):
        raw_flags = [
            b"flag{b64_flag_one}",
            b"HTB{b64_htb_secret}",
            b"THM{b64_thm_treasure}",
            b"picoCTF{b64_pico_flag}",
        ]
        b64_tokens = [base64.b64encode(f).decode("ascii") for f in raw_flags]
        text = f"Tokens: {' and '.join(b64_tokens)}"

        findings = find_flags_in_text(text, source="b64_test")
        flags = {f.flag_text for f in findings}
        for rf in raw_flags:
            flag_str = rf.decode("utf-8")
            assert flag_str in flags
            match = next(f for f in findings if f.flag_text == flag_str)
            assert match.format_type == "base64_decoded"
            assert match.source == "b64_test"

    def test_b64_encoded_legible_data_no_flag_format(self):
        secret_data = b"admin:SuperSecretCTFPassword123"
        b64_token = base64.b64encode(secret_data).decode("ascii")
        text = f"Authorization: Basic {b64_token}"

        findings = find_flags_in_text(text, source="auth")
        assert any(
            f.flag_text == "admin:SuperSecretCTFPassword123"
            and f.format_type == "base64_decoded"
            for f in findings
        )

    def test_b64_binary_garbage_ignored(self):
        # 32 random bytes will decode to unprintable binary
        garbage = base64.b64encode(os.urandom(32)).decode("ascii")
        text = f"Random data: {garbage}"
        findings = find_flags_in_text(text)
        assert len(findings) == 0


class TestHeadersAndBanners:
    """Unit tests for flag extraction from headers and banners."""

    def test_find_flags_in_headers_plain_and_b64(self):
        b64_flag = base64.b64encode(b"HTB{header_b64_token}").decode("ascii")
        headers = {
            "Server": "Apache/2.4.41 (Ubuntu) flag{header_server_flag}",
            "X-Powered-By": "PHP/7.4.3",
            "X-Debug-Token": b64_flag,
            "THM{flag_in_header_name}": "active",
        }

        findings = find_flags_in_headers(headers, source_prefix="http_header")
        flags = {f.flag_text for f in findings}

        assert "flag{header_server_flag}" in flags
        assert "HTB{header_b64_token}" in flags
        assert "THM{flag_in_header_name}" in flags

        # Check format types
        b64_f = next(f for f in findings if f.flag_text == "HTB{header_b64_token}")
        assert b64_f.format_type == "base64_decoded"
        assert "http_header:X-Debug-Token" in b64_f.source

        reg_f = next(f for f in findings if f.flag_text == "flag{header_server_flag}")
        assert reg_f.format_type == "regex"
        assert "http_header:Server" in reg_f.source

    def test_find_flags_in_headers_list_of_tuples(self):
        headers_list = [
            ("X-Flag", "flag{tuple_header_flag}"),
            ("Content-Type", "text/html"),
        ]
        findings = find_flags_in_headers(headers_list, source_prefix="header")
        assert len(findings) == 1
        assert findings[0].flag_text == "flag{tuple_header_flag}"

    def test_find_flags_in_headers_empty_and_invalid(self):
        assert find_flags_in_headers({}) == []
        assert find_flags_in_headers(None) == []
        assert find_flags_in_headers("not a dict") == []

    def test_scan_target_for_flags_orchestration(self):
        b64_banner_flag = base64.b64encode(b"THM{ftp_banner_b64_flag}").decode("ascii")
        banners = [
            "SSH-2.0-OpenSSH_8.2p1 Ubuntu flag{ssh_banner_flag}",
            f"220 FTP banner with secret {b64_banner_flag}",
            "",  # Empty banner
            None,  # None banner
        ]

        web_results = [
            WebTriageResult(
                url="http://10.10.10.10:80",
                status_code=200,
                server_header="Nginx flag{web_server_flag}",
                findings=["Disallow: /secret_flag{robots_flag}"],
                routes_checked=["/robots.txt", "/flag{route_flag}"],
                redirects=["302 -> http://10.10.10.10:80/flag{redirect_flag}"],
            )
        ]

        findings = scan_target_for_flags(banners=banners, web_results=web_results)
        flags = {f.flag_text for f in findings}

        assert "flag{ssh_banner_flag}" in flags
        assert "THM{ftp_banner_b64_flag}" in flags
        assert "flag{web_server_flag}" in flags
        assert "flag{robots_flag}" in flags
        assert "flag{route_flag}" in flags
        assert "flag{redirect_flag}" in flags

    def test_scan_target_for_flags_deduplication(self):
        # Repeated banners and headers with identical flag
        banners = [
            "Banner 1: flag{duplicate_flag}",
            "Banner 2: flag{duplicate_flag}",
        ]
        findings = scan_target_for_flags(banners=banners, web_results=[])
        # Banner source is "banner", both have identical flag_text, source, format_type
        # Deduplication should keep exactly 1 entry
        assert len(findings) == 1
        assert findings[0].flag_text == "flag{duplicate_flag}"


class TestEdgeCasesAndRobustness:
    """Unit tests for edge cases, corrupt data, and invalid inputs."""

    def test_empty_and_none_text(self):
        assert find_flags_in_text("") == []
        assert find_flags_in_text(None) == []
        assert find_flags_in_text(12345) == []

    def test_no_flags_in_normal_text(self):
        normal_text = (
            "Welcome to the portal. Please login with your credentials. "
            "System version 1.0.4. All rights reserved."
        )
        assert find_flags_in_text(normal_text) == []

    def test_incomplete_flag_patterns(self):
        incomplete = [
            "flag{",
            "flag}",
            "HTB{}",
            "THM{",
            "CTF",
            "just flag with no brackets",
        ]
        for item in incomplete:
            assert find_flags_in_text(item) == []

    def test_corrupt_blobs_and_binary_data_no_exception(self):
        # Mix of binary bytes, invalid base64 padding, and valid flag
        corrupt_text = (
            "Binary: \x00\x01\xfe\xff "
            "Corrupt b64: abc==== "
            "Valid: flag{resilient_matcher} "
            "More binary: \x07\x08\x1b"
        )
        findings = find_flags_in_text(corrupt_text)
        assert len(findings) == 1
        assert findings[0].flag_text == "flag{resilient_matcher}"

    def test_custom_regex_pattern(self):
        custom = [r"\bSECRET\{[^}]+\}"]
        text = "Found token: SECRET{custom_secret_pattern}"
        findings = find_flags_in_text(text, custom_patterns=custom)
        assert len(findings) == 1
        assert findings[0].flag_text == "SECRET{custom_secret_pattern}"
