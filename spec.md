# Especificación Técnica: CTF Recon & Triage CLI (`ctf-recon`)

## 1. Visión General
Herramienta de línea de comandos en Python diseñada para automatizar la fase de reconocimiento y triage inicial en retos CTF (Hack The Box, TryHackMe, Jeopardy). Realiza escaneo de servicios, detección web superficial, búsqueda de banderas/artefactos y sintetiza vectores de ataque mediante la API de Google Gemini.

## 2. Stack Tecnológico
- **Lenguaje:** Python 3.10+
- **CLI & Interfaz:** `typer` (parsing de comandos) y `rich` (tablas, paneles y spinners)
- **Networking & Web:** `asyncio` (sockets para barrido veloz) y `httpx` (cliente HTTP asíncrono)
- **Tipado & Validación:** `pydantic` v2
- **Motor LLM:** SDK oficial `google-genai` (Modelo: `gemini-2.5-flash` para latencia óptima)
- **Testing:** `pytest` / `unittest`

## 3. Comandos e Interfaz CLI
- `ctf-recon scan <TARGET>`:
  - Argumento requerido: `TARGET` (IP o dominio del reto).
  - Flags opcionales:
    - `-p, --ports <RANGE>`: Rango de puertos (por defecto: top 100 puertos comunes o `1-1000`).
    - `--ai`: Activa el análisis táctico asistido por Gemini.
    - `-m, --model <MODEL>`: Modelo de Gemini a utilizar (por defecto: `gemini-2.5-flash`).
    - `-o, --output <FILE>`: Exporta el reporte de triage a Markdown (por defecto: `writeup_triage.md`).
    - `--timeout <FLOAT>`: Timeout de conexión por puerto/petición en segundos (por defecto: `1.5`).

## 4. Módulos y Arquitectura
1. **`scanner/port_scanner.py`:** Barrido de puertos TCP asíncrono (`asyncio.open_connection`) con extracción de banners en servicios estándar.
2. **`scanner/web_triage.py`:** Si se detectan puertos HTTP/HTTPS, consulta la raíz y rutas clave (`/robots.txt`, `/.git/HEAD`), recolectando cabeceras (`Server`, `X-Powered-By`), redirecciones y código de estado.
3. **`triage/flag_matcher.py`:** Motor de expresiones regulares para identificar flags típicas (`flag{...}`, `HTB{...}`, `THM{...}`) y blobs Base64 en cabeceras o cuerpos HTML.
4. **`triage/ai_advisor.py`:** Envía la información estructurada del escaneo a Gemini exigiendo salida tipada JSON (Structured Outputs con Pydantic): CVEs probables, criticidad de servicios y comandos CLI sugeridos a continuación.
5. **`report/markdown_writer.py`:** Vuelca la evidencia a una plantilla de writeup en Markdown.

## 5. Criterios de Aceptación y Manejo de Errores
- Sin flags `--ai`, la herramienta debe funcionar 100% offline sin fallar por ausencia de `GEMINI_API_KEY`.
- Tiempos de escaneo controlados mediante semáforos de concurrencia (`asyncio.Semaphore`) para no saturar sockets locales.
- Manejo limpio de interrupciones de teclado (`Ctrl+C`) y hosts inaccesibles.