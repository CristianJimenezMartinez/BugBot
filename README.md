# 🛡️ BugBot v3.5 - Elite Hunter Engine

**BugBot** es un framework de alto rendimiento, semi-autónomo y modular diseñado para profesionales de **Bug Bounty** y **Pentesting**. Su objetivo es maximizar la eficiencia en la fase de Recon y Scanning, automatizando el triaje y la generación de reportes profesionales.

---

## 🚀 Capacidades Principales

### 🎯 Surgical Auditor (Auditoría Quirúrgica)
Análisis de profundidad variable en objetivos específicos. Combina crawling inteligente con validación activa de vulnerabilidades en tiempo real.

### 📊 Campaign Manager (Gestor de Campañas)
Diseñado para programas con *wildcards* amplios. Realiza OSINT masivo, descubrimiento de subdominios y escaneo paralelo de toda la infraestructura de una organización.

### 🧠 Memory Cortex (Persistencia Inteligente)
Motor de base de datos integrado que evita la duplicidad de hallazgos, gestiona el estado de los objetivos y aplica *rate-limiting* adaptativo para evitar baneos de WAF/CDN.

### 📡 OOB Engine (Out-of-Band Testing)
Integración nativa para la detección de vulnerabilidades ciegas (Blind SSRF, Out-of-Band LFI) mediante servidores de interacción, con validación automática de *callbacks*.

---

## 🛠️ Módulos Especializados (Arsenal)

- **🔍 OSINT & Recon:** Descubrimiento pasivo de subdominios con rotación de fuentes y verificación de hosts activos (HTTP/HTTPS).
- **📦 Frontend Ripper:** Extracción de rutas y secretos de archivos JavaScript, incluyendo desempaquetado automático de *Source Maps* (.js.map).
- **☁️ Cloud Hunter:** Auditoría automática de buckets mal configurados en AWS S3, Azure Blobs y Google Cloud Storage.
- **🕸️ GraphQL Architect:** Mapeo de endpoints GraphQL mediante introspección y sugerencia de consultas para APIs privadas.
- **🚩 Takeover Scanner:** Detección de *Subdomain Takeover* con soporte para más de 50 servicios en la nube populares.
- **🛡️ WAF & CORS Evasion:** Mutación avanzada de headers y bypass de configuraciones CORS inseguras para evadir controles de seguridad.

---

## 📝 Reportes Profesionales y Automáticos

BugBot no solo encuentra bugs, también ayuda a cobrarlos:
- **HackerOne Ready:** Generación de archivos Markdown con el formato exacto requerido por HackerOne.
- **Impacto y PoC:** Incluye descripciones de impacto técnico y comandos `curl` listos para reproducir el hallazgo.
- **Guía Táctica:** Incluye recomendaciones de explotación adicionales para escalar la vulnerabilidad.

---

## ⚙️ Instalación y Uso Rápido

### 1. Preparar el entorno
```bash
# Instalar dependencias
python -m pip install -r requirements.txt

# Configurar claves (opcional)
# Edita el archivo .env con tu GITHUB_TOKEN y otras APIs
```

### 2. Iniciar BugBot
```bash
# Modo Interactivo (Recomendado)
python main.py

# Auditoría rápida vía CLI
python main.py --target https://ejemplo.com --depth 2
```

---

## ⚖️ Aviso Ético
Este software ha sido creado exclusivamente con fines educativos y para su uso en programas de Bug Bounty autorizados. El autor no se hace responsable del uso indebido o daños causados por esta herramienta. **La autorización es obligatoria.**

---
*Desarrollado por [CristianJimenezMartinez](https://github.com/CristianJimenezMartinez) - Elite Hunter Edition.*
