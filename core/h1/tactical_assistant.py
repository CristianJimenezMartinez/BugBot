from typing import List
from core.h1.tier_manager import TierManager

class TacticalAssistant:
    """Inteligencia Táctica Independiente por tipo de hallazgo."""

    @staticmethod
    def generate_exploit_guide(secrets: List = None, fuzz_findings: List = None, takeovers: List = None, auth_findings: List = None, analyzer_findings: List = None, target: str = "") -> str:
        """Inteligencia Táctica Independiente por tipo de hallazgo."""
        secrets = secrets or []
        fuzz_findings = fuzz_findings or []
        takeovers = takeovers or []
        auth_findings = auth_findings or []
        analyzer_findings = analyzer_findings or []
        
        guide = "\n\n---\n# 🤖 [ÁREA SECRETA] CÓMO COBRAR ESTE BUG (Asistente Táctico para Noobs)\n\n"
        guide += "*Nota: Esta sección es secreta para ti, bórrala antes de enviar el reporte a HackerOne.*\n\n"
        
        # 1. Análisis de Tiers
        tier_manager = TierManager()
        tier_info = tier_manager.get_tier_info(target)
        guide += f"### 💰 Nivel de Recompensa (Reward Tiers)\n"
        guide += f"- Este objetivo (`{target}`) pertenece al **{tier_info['tier']}**.\n"
        guide += f"- {tier_info['desc']}\n\n"
        
        # 2. Guía Universal para XSS (Se mantiene como preventiva)
        guide += "### 🦠 Regla de Oro para XSS (Cross-Site Scripting)\n"
        guide += "- Si encuentras un **XSS Reflejado**, demuestra impacto real (PII o Account Takeover) para cobrar bien.\n"
        guide += "- **💡 PoC Inofensiva:** `<svg/onload=confirm('Hacked_by_BugBot')>`\n\n"
        
        # Guía para Takeovers
        if takeovers:
            guide += "### ☠️🌐 ¡ALERTA CRÍTICA! SUBDOMAIN TAKEOVER DETECTADO\n"
            guide += "- **El Problema:** El subdominio apunta a un servicio Cloud abandonado.\n"
            guide += "- **Cómo Explotar:** Registra el servicio con el nombre exacto, aloja un HTML de prueba y reporta impacto crítico.\n\n"
        
        # Guía para PII
        if any("PII:" in s.get('tipo_secreto', '') for s in secrets):
            guide += "### 👤🛡️ PII EXPOSURE DETECTADO (CAMPAÑA DOUBLE BOUNTY ACTIVA)\n"
            guide += "- **Cómo Explotar:** Verifica que los datos son de usuarios reales. Menciona la campaña de Double Bounty en tu reporte.\n\n"
        
        # Guía para Secretos Generales
        if any(s.get('tipo_secreto') != "SOURCEMAP_EXPOSED" and "PII:" not in s.get('tipo_secreto', '') for s in secrets) or analyzer_findings:
            guide += "### 🔑 Encontraste Llaves o Secretos de Alta Entropía\n"
            guide += "- **Cómo Explotar:** Valida la llave con KeyHacks. Si da acceso a DBs o emails, es CRÍTICO.\n\n"
                
        # Guía para Sourcemaps
        if any(s.get('tipo_secreto') == "SOURCEMAP_EXPOSED" for s in secrets):
            guide += "### 📦⚛️ ¡PREMIO GORDO! SOURCEMAP EXPUESTO (.js.map)\n"
            guide += "- **Cómo Explotar:** Usa Source Map Unpacker para recuperar el código fuente original y buscar claves o rutas de admin.\n\n"
            
        # Guía para Fuzzing (Robots/Sitemap)
        if any("robots.txt" in ff.get('path', '') or "sitemap.xml" in ff.get('path', '') for ff in fuzz_findings):
            guide += "### 🗺️ Encontraste Robots.txt / Sitemap.xml\n"
            guide += "- **Cómo Explotar:** Visita las rutas `Disallow`. Si entras a un panel sin auth, ese es el bug real.\n"
            
            for ff in fuzz_findings:
                if "robots.txt" in ff.get('path', '') or "sitemap.xml" in ff.get('path', ''):
                    juicy = ff.get('juicy_extracted', [])
                    if juicy:
                        guide += "  🔥 **Hallazgos de BugBot:**\n"
                        for j in juicy[:5]: guide += f"    - `{j}`\n"
            guide += "\n"

        # Guía para IDOR / BOLA
        if auth_findings:
            guide += "### 👥 Posible IDOR o Modificación de Parámetros\n"
            guide += "- **Cómo Explotar:** Usa dos cuentas (A y B). Si la Cuenta B puede ver o modificar datos de la Cuenta A cambiando el ID, es un IDOR crítico.\n\n"

        return guide
