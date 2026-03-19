import asyncio
import os
import logging
from datetime import datetime
from core.enumerator import SubdomainEnumerator
from core.pipeline.auditor import SurgicalAuditor
from core.config import Config
from core.file_manager import FileManager

logger = logging.getLogger("BugBot.Pipeline.Campaign")

class CampaignManager:
    """Gestor atómico para campañas masivas OSINT."""
    
    def __init__(self, depth: int = 1):
        self.depth = depth
        self.auditor = SurgicalAuditor()
        self.all_campaign_findings = []

    async def run(self, domain: str, project_name: str):
        """Ejecuta una campaña masiva sobre un dominio raíz."""
        print(f"\n\033[95m[🚀] INICIANDO CAMPAÑA MASIVA: {domain}\033[0m")
        
        enumerator = SubdomainEnumerator()
        targets = await enumerator.enumerate(domain)
        if not targets:
            print(f"[-] No se encontraron subdominios para {domain}.")
            return
            
        targets = sorted(list(set(targets)))
        osint_file = os.path.join(Config.DATA_DIR, f"osint_targets_{domain.replace('.', '_')}.txt")
        with open(osint_file, "w", encoding="utf-8") as f:
            for t in targets: f.write(t + "\n")
            
        print(f"[*] Inteligencia OSINT guardada: {osint_file}")
        
        for idx, target in enumerate(targets, 1):
            print(f"\n\033[93m[🎯] {idx}/{len(targets)}: {target}\033[0m")
            try:
                findings = await self.auditor.run(target, depth=self.depth, project=project_name)
                if findings:
                    for f in findings:
                        f['_campaign_target'] = target
                    self.all_campaign_findings.extend(findings)
            except Exception as e:
                print(f"[-] Error auditando {target}: {e}")
            
            # Delay entre targets para evitar ban masivo
            await asyncio.sleep(10)
        
        # Generar resumen de findings críticos
        self._generate_critical_summary(domain)
            
        print(f"\n\033[92m[🏁] CAMPAÑA MASIVA FINALIZADA SOBRE: {domain}\033[0m")
        return targets

    def _generate_critical_summary(self, domain: str):
        """Genera CRITICAL_FINDINGS.md con solo los hallazgos que valen dinero."""
        if not self.all_campaign_findings:
            print(f"\n[*] Campaña limpia: 0 findings en {domain}")
            return
        
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Filtrar solo findings que pagan en HackerOne
        critical_types = ["CRITICAL", "HIGH"]
        live_keywords = ["🔥", "LIVE", "BYPASSED", "TAKEOVER", "CONFIRMED", "BLIND_SSRF"]
        
        money_findings = []
        noise_findings = []
        
        for f in self.all_campaign_findings:
            severity = str(f.get('severity', f.get('impacto', 'LOW'))).upper()
            tipo = str(f.get('tipo', f.get('tipo_secreto', '')))
            is_live = f.get('validated') is True
            
            is_critical = (
                severity in critical_types or
                is_live or
                any(kw in tipo for kw in live_keywords)
            )
            
            if is_critical:
                money_findings.append(f)
            else:
                noise_findings.append(f)
        
        # Construir el archivo
        content = f"# 💰 CRITICAL FINDINGS: {domain}\n"
        content += f"**Campaña:** {now}\n"
        content += f"**Total findings:** {len(self.all_campaign_findings)} | **💰 Reportables:** {len(money_findings)} | **Descartados:** {len(noise_findings)}\n\n"
        
        if not money_findings:
            content += "> ⚠️ No se encontraron findings CRITICAL/HIGH en esta campaña.\n"
            content += f"> Se descartaron {len(noise_findings)} findings de baja severidad.\n"
        else:
            content += "---\n\n"
            for i, f in enumerate(money_findings, 1):
                tipo = f.get('tipo', f.get('tipo_secreto', 'UNKNOWN'))
                severity = f.get('severity', f.get('impacto', 'HIGH'))
                url = f.get('url', f.get('url_archivo', 'N/A'))
                target = f.get('_campaign_target', 'N/A')
                detalles = f.get('detalles', f.get('validation_details', ''))
                curl_poc = f.get('curl_poc', '')
                
                content += f"## {i}. {tipo}\n"
                content += f"- **Severidad:** `{severity}`\n"
                content += f"- **Target:** `{target}`\n"
                content += f"- **URL:** `{url}`\n"
                if detalles:
                    content += f"- **Detalles:** {detalles}\n"
                if curl_poc:
                    content += f"- **PoC:**\n```bash\n{curl_poc}\n```\n"
                content += "\n"
        
        # Guardar
        target_path = Config.get_target_path(domain)
        os.makedirs(target_path, exist_ok=True)
        path = os.path.join(target_path, "CRITICAL_FINDINGS.md")
        FileManager.write_file(path, content)
        
        print(f"\n\033[91m{'='*60}\033[0m")
        print(f"\033[91m  💰 CRITICAL FINDINGS: {len(money_findings)} reportables\033[0m")
        print(f"\033[91m  📄 Archivo: {path}\033[0m")
        print(f"\033[91m{'='*60}\033[0m")

