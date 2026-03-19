import asyncio
import aiohttp
import copy
import logging
from typing import Dict, Optional, List
from core.config import Config
from core.auth.fingerprint import SessionFingerprinter
from core.auth.comparator import AuthComparator
from core.auth.payloads import AuthPayloadGenerator

logger = logging.getLogger("BugBot.Auth.Engine")

class AuthEngine:
    """Motor de ejecución atómico para pruebas diferenciales."""
    
    def __init__(self, session_A: dict, session_B: dict = None, timeout: int = 15):
        self.session_A = session_A
        self.session_B = session_B
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.payload_gen = AuthPayloadGenerator()
        self.comparator = AuthComparator()
        self.fingerprinter = SessionFingerprinter()

    async def execute_request(self, session, method: str, url: str, headers: dict, data=None, json=None) -> Dict:
        """Ejecuta una petición y devuelve metadatos estandarizados."""
        try:
            async with session.request(method, url, headers=headers, data=data, json=json, timeout=self.timeout, allow_redirects=False) as resp:
                content = await resp.read()
                return {
                    "status": resp.status,
                    "size": len(content),
                    "content": content.decode('utf-8', errors='ignore'),
                    "headers": resp.headers
                }
        except Exception as e:
            return {"status": 0, "size": 0, "content": "", "error": str(e)}

    async def test_idor(self, session, req: dict) -> Optional[Dict]:
        """Lógica atómica de test diferencial IDOR."""
        url = req['url']
        method = req.get('method', 'GET').upper()
        
        # --- Baseline A ---
        headers_A = copy.deepcopy(Config.CUSTOM_HEADERS)
        headers_A.update(self.session_A)
        res_A = await self.execute_request(session, method, url, headers_A, req.get('post_data'), req.get('json'))
        
        if self.comparator.is_access_denied(res_A['status']): return None

        # --- Attack B (Horizontal) ---
        if self.session_B:
            headers_B = copy.deepcopy(Config.CUSTOM_HEADERS)
            headers_B.update(self.session_B)
            res_B = await self.execute_request(session, method, url, headers_B, req.get('post_data'), req.get('json'))
            
            if self.comparator.is_similar(res_A, res_B):
                # Verificamos si también es público (Falso Positivo)
                res_Pub = await self.execute_request(session, method, url, Config.CUSTOM_HEADERS)
                if self.comparator.is_access_denied(res_Pub['status']):
                    return {
                        "url": url,
                        "tipo": f"IDOR / BOLA ({method})",
                        "impacto": "CRITICAL",
                        "detalles": "Usuario B accedió a datos de Usuario A."
                    }

        # --- Attack Lone Wolf (Increment) ---
        mutated_url = self.payload_gen.mutate_numeric_id(url)
        if mutated_url:
            res_Mut = await self.execute_request(session, method, mutated_url, headers_A)
            if res_Mut['status'] in [200, 201] and res_Mut['size'] > 100:
                return {
                    "url": mutated_url,
                    "tipo": "SINGLE-USER IDOR",
                    "impacto": "HIGH",
                    "detalles": "Acceso exitoso a ID incrementado."
                }
        
        return None
