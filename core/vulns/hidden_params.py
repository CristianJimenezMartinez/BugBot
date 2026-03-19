import logging
from typing import Optional, Dict, List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.vulns.base import VulnScannerBase

logger = logging.getLogger("BugBot.Vulns.HiddenParams")

class HiddenParamsScanner(VulnScannerBase):
    """
    Motor atómico para descubrimiento de parámetros ocultos (Arjun-lite).
    Inyecta parámetros comunes y detecta cambios en el comportamiento del servidor.
    """
    
    # Parámetros que frecuentemente exponen funcionalidad oculta en Bug Bounty
    COMMON_PARAMS = [
        # Auth & Privilege Escalation
        "admin", "debug", "test", "role", "is_admin", "isAdmin",
        "access_level", "user_role", "privileged", "internal",
        # IDOR / Data Exposure
        "id", "user_id", "uid", "account_id", "org_id", "email", "username",
        # Debug / Info Disclosure
        "debug", "verbose", "trace", "dev", "testing", "show_errors",
        "detailed", "raw", "format", "output", "mode",
        # SSRF / Redirect
        "url", "redirect", "next", "return", "callback", "continue",
        "dest", "destination", "redir", "redirect_uri", "return_to",
        # File / Path
        "file", "path", "template", "page", "view", "include", "doc",
        "folder", "root", "dir",
        # API / Config
        "api_key", "token", "secret", "key", "config", "version",
        "v", "fields", "include", "expand", "embed",
        # Pagination / Filter (useful for data scraping)
        "limit", "offset", "per_page", "page_size", "sort", "order",
    ]

    async def check(self, url: str) -> Optional[Dict]:
        """Fuzea parámetros ocultos comparando respuestas."""
        parsed = urlparse(url)
        
        # Solo fuzzear URLs con paths interesantes (no la raíz)
        if not parsed.path or parsed.path == "/":
            return None
        
        # Solo si la URL tiene potencial (API, admin, dashboard, etc.)
        interesting_paths = ["api", "admin", "dashboard", "account", "user", 
                           "settings", "config", "internal", "graphql", "v1", "v2", "v3"]
        path_lower = parsed.path.lower()
        if not any(kw in path_lower for kw in interesting_paths):
            return None

        # 1. Baseline: Petición sin parámetros extra
        baseline = await self._safe_get(url)
        if not baseline:
            return None
        
        baseline_size = len(baseline["content"])
        baseline_status = baseline["status"]
        
        # 2. Fuzz: Inyectar cada parámetro y comparar
        hits = []
        existing_params = parse_qs(parsed.query)
        
        for param in self.COMMON_PARAMS:
            # Skip si el parámetro ya existe en la URL
            if param in existing_params:
                continue
            
            # Construir URL con el parámetro inyectado
            test_params = dict(existing_params)
            test_params[param] = ["true"]
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))
            
            res = await self._safe_get(test_url)
            if not res:
                continue
            
            # Detección de comportamiento anómalo
            size_diff = abs(len(res["content"]) - baseline_size)
            status_changed = res["status"] != baseline_status
            
            # Hit si: status diferente O tamaño varía más del 10% (y al menos 100 bytes)
            is_hit = False
            reason = ""
            
            if status_changed and res["status"] not in [403, 429, 503]:
                is_hit = True
                reason = f"Status changed: {baseline_status} → {res['status']}"
            
            if size_diff > max(100, baseline_size * 0.1):
                is_hit = True
                reason = f"Response size changed: {baseline_size} → {len(res['content'])} ({size_diff:+d} bytes)"
            
            # Detección de debug/error disclosure
            debug_indicators = ["stack trace", "traceback", "exception", "debug=", 
                              "sql", "query", "internal server", "verbose"]
            if any(ind in res["content"].lower() for ind in debug_indicators):
                if not any(ind in baseline["content"].lower() for ind in debug_indicators):
                    is_hit = True
                    reason = "Debug/Error information disclosed with parameter injection"
        
            if is_hit:
                hits.append({"param": param, "reason": reason, "url": test_url})
                # Limitar a 5 hits para no saturar
                if len(hits) >= 5:
                    break
        
        if hits:
            details_parts = [f"`{h['param']}` → {h['reason']}" for h in hits]
            return {
                "url": url,
                "tipo": "HIDDEN_PARAMS_FOUND",
                "impacto": "MEDIUM",
                "detalles": f"Parámetros ocultos descubiertos: {'; '.join(details_parts)}",
                "hits": hits
            }
        
        return None
