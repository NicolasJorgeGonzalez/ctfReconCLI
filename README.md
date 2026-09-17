# `ctf-recon` 🎯

Herramienta de línea de comandos (CLI) asíncrona en Python diseñada para automatizar la fase de **reconocimiento y triage inicial en retos CTF** (Hack The Box, TryHackMe, Jeopardy, FaMAF CTF).

Realiza escaneo veloz de puertos TCP, triage superficial de aplicaciones web, detección automatizada de banderas y artefactos codificados en Base64, y sintetiza vectores de ataque tácticos utilizando la API oficial de **Google Gemini**.

---

## 🚀 Características Principales

- **⚡ Escaneo de Puertos Asíncrono:** Barrido TCP veloz con `asyncio` y control de concurrencia mediante semáforos (`asyncio.Semaphore`) para evitar saturación de descriptores de sockets locales. Incluye extracción automática de banners (banner grabbing).
- **🌐 Triage Web Automático:** Para puertos HTTP/HTTPS detectados, inspecciona la raíz (`/`) y rutas clave como `/robots.txt` y `/.git/HEAD`, recolectando cabeceras diagnósticas (`Server`, `X-Powered-By`), códigos de estado y cadenas de redirección.
- **🚩 Motor de Detección de Banderas y Blobs:** Búsqueda mediante expresiones regulares de banderas en formatos estándar (`FaMAF{...}`, `HTB{...}`, `THM{...}`, `flag{...}`, `picoCTF{...}`) y detección/decodificación segura de blobs Base64 en banners y respuestas HTTP.
- **🤖 Asesor Táctico con IA (Google Gemini):** Análisis asistido con el SDK oficial `google-genai` que genera reportes estructurados con Pydantic: evaluación de criticidad de servicios, CVEs probables, comandos de consola sugeridos a continuación y vectores de ataque recomendados.
- **🎛️ Selección Dinámica de Modelos:** Posibilidad de elegir el modelo de Gemini a través del flag `-m` / `--model` (por defecto: `gemini-2.5-flash`).
- **🔌 100% Funcional Offline:** Si no se utiliza el flag `--ai`, la herramienta opera completamente desconectada sin requerir `GEMINI_API_KEY` ni conexión externa a Google.
- **📝 Exportación a Markdown:** Genera automáticamente un writeup estructurado en Markdown (`writeup_triage.md`) listo para documentar retos o reportar auditorías.
- **🎨 Interfaz de Terminal Moderna:** Construida con `typer` y `rich` con spinners de progreso, tablas formateadas y paneles de alerta destacados al encontrar banderas.

---

## 📋 Requisitos

- Python **3.10** o superior.
- Clave de API de Google Gemini (opcional, requerida únicamente si se usa `--ai`).

---

## 📦 Instalación

### 1. Clonar el repositorio
```bash
git clone https://github.com/NicolasJorgeGonzalez/ctfReconCLI.git
cd ctfReconCLI
```

### 2. Crear y activar el entorno virtual
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Instalar la herramienta
```bash
# Instalación estándar
pip install .

# O en modo desarrollo (incluye dependencias de testing pytest)
pip install -e ".[dev]"
```

Una vez instalado, el comando `ctf-recon` estará disponible directamente en tu terminal.

---

## 🔑 Configuración de Gemini (Opcional)

Si deseas utilizar el análisis táctico con IA, define tu clave de API como variable de entorno:

```bash
export GEMINI_API_KEY="tu_api_key_aqui"
```

> **Nota:** Puedes obtener una API key gratuita en [Google AI Studio](https://aistudio.google.com/).

---

## 📖 Modo de Uso

### Comando Básico
Escanear un objetivo (los 100 puertos CTF más comunes por defecto):
```bash
ctf-recon scan 10.10.10.10
```

### Escaneo con Rango o Lista de Puertos
```bash
# Rango de puertos
ctf-recon scan 10.10.10.10 -p 1-1000

# Puertos específicos
ctf-recon scan 10.10.10.10 -p 80,443,8080,8443

# Combinaciones mixtas
ctf-recon scan 10.10.10.10 -p 22,80,8000-8020
```

### Escaneo Asistido con Inteligencia Artificial
```bash
# Usando el modelo por defecto (gemini-2.5-flash)
ctf-recon scan 10.10.10.10 --ai

# Pasando la API Key como argumento en la llamada
ctf-recon scan 10.10.10.10 -k "tu_gemini_api_key"
ctf-recon scan 10.10.10.10 --key "tu_gemini_api_key" --model gemini-1.5-pro

# Especificando un modelo personalizado de Gemini
ctf-recon scan 10.10.10.10 --ai -m gemini-1.5-pro
ctf-recon scan 10.10.10.10 --ai --model gemini-2.0-flash
```

### Exportar el Reporte a un Archivo Específico
Por defecto, el reporte se guarda en `writeup_triage.md`. Puedes personalizar la ruta con `-o` o `--output`:
```bash
ctf-recon scan 10.10.10.10 -o reportes/maquina_htb.md
```

### Ajustar el Timeout por Conexión
```bash
ctf-recon scan 10.10.10.10 --timeout 2.5
```

### Ver Ayuda y Opciones
```bash
ctf-recon scan --help
```

---

## ⚙️ Resumen de Opciones del CLI

| Argumento / Flag | Alias | Descripción | Valor por Defecto |
| :--- | :--- | :--- | :--- |
| `TARGET` | — | IP o dominio del reto objetivo (requerido) | — |
| `--ports` | `-p` | Rango o lista de puertos a escanear | Top 100 comunes |
| `--ai` | — | Activa el análisis táctico asistido por Gemini | `False` |
| `--key` | `-k`, `--api-key` | Clave de API de Google Gemini (o variable `GEMINI_API_KEY`) | `None` |
| `--model` | `-m` | Modelo de Gemini para el análisis | `gemini-2.5-flash` |
| `--output` | `-o` | Ruta del archivo Markdown de salida | `writeup_triage.md` |
| `--timeout` | — | Timeout por puerto/petición en segundos | `1.5` |
| `--help` | — | Muestra la ayuda y sale | — |

---

## 🧪 Ejecución de Tests

El proyecto cuenta con una suite completa de pruebas unitarias y de integración:

```bash
# Ejecutar todas las pruebas
pytest

# Ejecutar con salida detallada
pytest -v
```

---

## 📁 Estructura del Proyecto

```text
ctfReconCLI/
├── pyproject.toml              # Definición del paquete y dependencias
├── spec.md                     # Especificación técnica original
├── tasks.md                    # Roadmap de tareas implementadas
├── README.md                   # Documentación de uso e instalación
├── ctf_recon/
│   ├── __init__.py             # Inicialización y exportación de modelos
│   ├── cli.py                  # Interfaz CLI con Typer y Rich
│   ├── models.py               # Modelos de datos Pydantic v2
│   ├── scanner/
│   │   ├── port_scanner.py     # Escáner de puertos asíncrono
│   │   └── web_triage.py       # Triage superficial HTTP/HTTPS
│   ├── triage/
│   │   ├── flag_matcher.py     # Detección regex y decodificación Base64
│   │   └── ai_advisor.py       # Integración con Google Gemini (google-genai)
│   └── report/
│       └── markdown_writer.py  # Generador de writeup en Markdown
└── tests/                      # Suite de tests con pytest
```

---

## 📄 Licencia

Este proyecto está disponible bajo la licencia MIT.
