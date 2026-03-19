import os
import asyncio
import shutil
import logging
from typing import List, Dict
from urllib.parse import urlparse
from datetime import datetime

from core.config import Config
from core.project_manager import ProjectManager
from core.memory_cortex import MemoryCortex
from core.headless_crawler import HeadlessCrawler as Crawler
from core.vulnerability_check import VulnerabilityCheck
from core.scanner import Scanner
from core.fuzzer import Fuzzer
from core.triage_engine import TriageEngine
from core.file_manager import FileManager
from core.takeover import TakeoverScanner
from core.cors_checker import CorsChecker
from core.auth_tester import AuthTester
from core.file_analyzer import FileAnalyzer
from core.cloud_hunter import CloudBucketHunter
from core.graphql_mapper import GraphQLMapper
from core.frontend_ripper import FrontendRipper
from core.h1_formatter import H1Formatter

logger = logging.getLogger("BugBot.Pipeline.Auditor")

class SurgicalAuditor:
    """Motor central atómico para la auditoría de un único host."""
    
    def __init__(self, concurrency: int = None):
        self.concurrency = concurrency or Config.MODULE_CONCURRENCY
        self.cortex = MemoryCortex()

    async def run(self, target_url: str, depth: int = 1, project: str = None) -> List[Dict]:
        """Ejecuta toda la pipeline ofensiva sobre un target."""
        if project:
            if not Config.load_project(project):
                print(f"[!] Aviso: No se pudo cargar el proyecto {project}. Usando config por defecto.")
        
        print(f"\n[*] INICIANDO AUDITORÍA QUIRÚRGICA EN: {target_url}")
        parsed = urlparse(target_url if target_url.startswith("http") else f"https://{target_url}")
        domain_to_check = parsed.netloc.lower() if parsed.netloc else target_url.lower()
        
        for ooc in Config.OUT_OF_SCOPE_DOMAINS:
            if domain_to_check == ooc or domain_to_check.endswith("." + ooc):
                print(f"\n\033[91m[!] ABORTADO: El objetivo {target_url} está FUERA DE ALCANCE.\033[0m")
                return []
                
        if not target_url.startswith("http"):
            target_url = f"https://{target_url}"
                
        # Phase 0. Takeover
        takeover_scanner = TakeoverScanner()
        takeover_finding = await takeover_scanner.scan(target_url)
        takeovers = [takeover_finding] if takeover_finding else []
            
        # Phase 1. Discovery
        crawler = Crawler(concurrency=self.concurrency)
        crawl_data = await crawler.run([target_url], max_depth=depth)
        
        all_urls, js_urls, api_urls = [], [], []
        for host_url, data in crawl_data.items():
            all_urls.extend(data.get('links_internos', []))
            js_urls.extend(data.get('archivos_js', []))
            api_urls.extend(data.get('api_endpoints', []))
        
        js_urls = sorted(list(set(js_urls)))
        all_urls = sorted(list(set(all_urls)))
        api_urls_flat = sorted(list(set([req['url'] for req in api_urls])))
        param_urls = sorted(list(set(api_urls_flat + [u for u in all_urls if "?" in u or any(kw in u.lower() for kw in Config.INTEREST_KEYWORDS)])))
        
        if js_urls:
            ripper = FrontendRipper(target_domain=domain_to_check)
            ripped_routes = await ripper.run(js_urls)
            if ripped_routes:
                all_urls = sorted(list(set(all_urls + ripped_routes)))
                # Conectar rutas ripped al pipeline de vulns (SSRF/IDOR/LFI)
                ripped_api_urls = [u for u in ripped_routes if any(kw in u.lower() for kw in ["api", "v1", "v2", "v3", "graphql", "admin", "user", "account", "config", "internal", "?"])]
                if ripped_api_urls:
                    param_urls = sorted(list(set(param_urls + ripped_api_urls)))
                    print(f"[{domain_to_check}] [+] Ripper: {len(ripped_api_urls)} rutas API inyectadas al VulnScanner")

        print(f"[{domain_to_check}] [+] Pipeline Desplegada con {len(all_urls)} endpoints detectados.")

        # Pipeline Ofensiva Concurrente
        async def _run_cors(): return await CorsChecker(concurrency=self.concurrency).run(all_urls) if all_urls else []
        async def _run_secrets(): return await Scanner(concurrency=self.concurrency).run(js_urls) if js_urls else []
        async def _run_vulns():
            if not param_urls: return []
            checker = VulnerabilityCheck(concurrency=1)
            await checker.initialize()
            poll_task = asyncio.create_task(checker.oob.poll_interactions(duration_minutes=3))
            findings = await checker.run_discovery(param_urls)
            await poll_task
            return findings + (checker.oob.findings if checker.oob.findings else [])
        async def _run_fuzzer(): return await Fuzzer(concurrency=self.concurrency).run([target_url])
        async def _run_cloud(): return await CloudBucketHunter(concurrency=50).run(domain_to_check, known_subdomains=[domain_to_check])
        async def _run_graphql(): return await GraphQLMapper(concurrency=10).run(target_url)

        findings_group = await asyncio.gather(_run_cors(), _run_secrets(), _run_vulns(), _run_fuzzer(), _run_cloud(), _run_graphql(), return_exceptions=True)
        
        # Procesar Hallazgos
        all_findings = takeovers
        for res in findings_group:
            if isinstance(res, list): all_findings.extend(res)
            
        if all_findings:
            self._save_reports(target_url, domain_to_check, all_findings)
            
        return all_findings

    def _save_reports(self, target_url: str, domain: str, findings: List[Dict]):
        """Generación atómica de reportes."""
        target_path = Config.get_target_path(domain)
        os.makedirs(target_path, exist_ok=True)
        path = os.path.join(target_path, "findings_summary.md")
        
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        content = f"# 🏹 Findings Summary: {target_url}\n**Fecha:** {now}\n\n| Tipo | Impacto | Detalle |\n"
        content += "| :--- | :--- | :--- |\n"
        
        # Deduplicar findings por tipo+url
        seen = set()
        for f in findings:
            tipo = f.get('finding_type', f.get('tipo', f.get('tipo_secreto', 'VULN')))
            severidad = f.get('severity', f.get('impacto', 'MEDIUM'))
            url = f.get('url', f.get('url_archivo', 'N/A'))
            dedup_key = f"{tipo}|{url}|{f.get('match', '')}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            content += f"| {tipo} | **{severidad}** | `{url}` |\n"
            
        FileManager.write_file(path, content)
        print(f"\n[🔥] HALLAZGOS GUARDADOS EN: {path}")
        
        # H1 Auto-Reporting
        h1 = H1Formatter(target=target_url)
        h1_path = h1.save_h1_report(h1.format_report(findings=findings))
        print(f" -> \033[96m[📝] REPORTE TÁCTICO H1: {h1_path}\033[0m")
        
        triage = TriageEngine(domain)
        for f in findings:
            finding_url = f.get('url', f.get('url_archivo', ''))
            if not triage.is_false_positive(finding_url, ""):
                triage.generate_hackerone_report({
                    "bug_type": f.get('tipo', f.get('tipo_secreto', 'UNSECURE')),
                    "target_url": finding_url,
                    "curl_poc": f.get('curl_poc', f'curl -i "{finding_url}"'),
                    "impact_description": f.get('detalles', f.get('validation_details', 'Exposición de datos.')),
                    "validation_details": f.get('validation_details', ''),
                    "waf_bypass_headers": f.get('headers_inyectados', {})
                })
