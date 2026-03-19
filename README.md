# 🛡️ BountyBot v1.0 - Sistema de Automatización para Bug Bounty

Este sistema ha sido diseñado para maximizar la eficiencia en la búsqueda de vulnerabilidades y la generación de reportes profesionales.

## 📁 Estructura del Proyecto
- `core/`: Lógica principal (Recon, Checker, Crawler, Scanner, Reporter).
- `utils/`: Herramientas auxiliares (Logging).
- `targets/`: Resultados organizados por dominio.
- `venv/`: Entorno virtual aislado.

## 🚀 Cómo usarlo

1. **Instalar dependencias:**
   ```powershell
   python -m pip install -r requirements.txt
   ```

2. **Ejecutar el escáner:**
   ```powershell
   python main.py ejemplo.com
   ```

3. **Ver resultados:**
   Revisa la carpeta `targets/ejemplo.com/report.md`.

## 🛠️ Módulos Incluidos
- **Recon:** Búsqueda pasiva de subdominios vía `crt.sh`.
- **Checker:** Verificación asíncrona de hosts vivos (HTTP/HTTPS).
- **Crawler:** Extracción automática de enlaces y archivos JavaScript.
- **Scanner:** Búsqueda de secretos (API Keys, Tokens) usando Regex profesional.
- **Reporter:** Generación automática de reportes profesionales listos para enviar.

---
*Desarrollado para la victoria en Bug Bounty.*
