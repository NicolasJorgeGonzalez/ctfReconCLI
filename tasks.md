# Implementation Tasks: `ctf-recon` CLI

This task list details the step-by-step implementation plan for building the `ctf-recon` CLI tool according to `spec.md`.

---

## Task 1: Project Setup & Package Structure
- [x] Initialize Python package layout (`src/ctf_recon/` or `ctf_recon/`).
- [x] Create `pyproject.toml` with dependencies: `typer`, `rich`, `httpx`, `pydantic>=2.0`, `google-genai`, `pytest`, `pytest-asyncio`.
- [x] Create basic entrypoint script and module `__init__.py` files.
- [x] Setup unit test layout in `tests/`.

---

## Task 2: Core Data Models (`ctf_recon/models.py`)
- [x] Define Pydantic v2 schemas:
  - `PortScanResult`: port, state, banner, protocol.
  - `WebTriageResult`: url, status_code, server_header, x_powered_by, redirects, findings, routes_checked.
  - `FlagFinding`: flag_text, source (header, body, route), format_type (standard regex vs base64 decoded).
  - `AIAnalysisResult`: probable_cves, service_criticality, suggested_cli_commands, attack_vectors.
  - `TriageReport`: target, scan_timestamp, open_ports, web_findings, flags_found, ai_analysis.

---

## Task 3: Async Port Scanner (`ctf_recon/scanner/port_scanner.py`)
- [x] Implement port parsing logic (`1-1000`, comma-separated ports, top ports list).
- [x] Implement `async scan_ports(target, ports, timeout, max_concurrency)` using `asyncio.open_connection`.
- [x] Extract service banners where available.
- [x] Handle connection timeouts and connection refused gracefully.
- [x] Control concurrency using `asyncio.Semaphore`.

---

## Task 4: Web Triage Scanner (`ctf_recon/scanner/web_triage.py`)
- [ ] Implement HTTP/HTTPS probe for web ports (e.g., 80, 443, 8080, 8443, etc.).
- [ ] Fetch key routes: `/`, `/robots.txt`, `/.git/HEAD`.
- [ ] Extract headers (`Server`, `X-Powered-By`, custom headers) and check for redirects.
- [ ] Handle SSL errors, connection timeouts, and HTTP errors gracefully using `httpx.AsyncClient`.

---

## Task 5: Flag & Blob Engine (`ctf_recon/triage/flag_matcher.py`)
- [ ] Implement regex patterns for common CTF flags (`flag{...}`, `HTB{...}`, `THM{...}`, `CTF{...}`).
- [ ] Implement Base64 detection regex and safe decoding logic to discover encoded flags/tokens in headers or body content.
- [ ] Search within HTTP response bodies, response headers, and scanned banners.

---

## Task 6: Gemini AI Advisor (`ctf_recon/triage/ai_advisor.py`)
- [ ] Implement `AIAdvisor` using official `google-genai` SDK and model `gemini-2.5-flash`.
- [ ] Use Pydantic Structured Outputs (`response_schema` / structured format) to strictly format AI response into `AIAnalysisResult`.
- [ ] Ensure offline graceful degradation: if `--ai` is not passed or `GEMINI_API_KEY` is missing/empty, return `None` or log warning without crashing.

---

## Task 7: Markdown Report Generator (`ctf_recon/report/markdown_writer.py`)
- [ ] Design clean writeup Markdown template.
- [ ] Export `TriageReport` to file (default `writeup_triage.md` or user `-o` argument).
- [ ] Format tables for open ports, web findings, discovered flags/artefacts, and AI recommendations.

---

## Task 8: CLI Interface & Rich Formatting (`ctf_recon/cli.py`)
- [ ] Build `typer` app with `scan` command accepting:
  - `TARGET` (required arg)
  - `-p, --ports` (default: `1-1000` or common top ports)
  - `--ai` (flag boolean)
  - `-o, --output` (default: `writeup_triage.md`)
  - `--timeout` (float, default: `1.5`)
- [ ] Implement Rich UI components: spinners during port scan & web triage, formatted Rich tables for output, colorful alert panels for flags.
- [ ] Implement clean `Ctrl+C` (`KeyboardInterrupt`) handling and error messages.

---

## Task 9: Unit Testing & Verification (`tests/`)
- [ ] Unit tests for `port_scanner` (mocking socket connections).
- [ ] Unit tests for `web_triage` (using `httpx` mock / `respx`).
- [ ] Unit tests for `flag_matcher` with various regex pattern test cases and base64 strings.
- [ ] Unit tests for `ai_advisor` (mocking `google-genai` response).
- [ ] Integration test for CLI `scan` command.
