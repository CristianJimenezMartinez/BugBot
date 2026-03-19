"""
BugBot v3.5 - Session Manager (Gestor de Sesiones con Kill Switch)

Implementa:
- Inyección automática de cabeceras de identificación H1.
- Contador global asíncrono de peticiones diarias.
- Kill Switch obligatorio al alcanzar el umbral configurado.
- Soporte para rate limiting por endpoint.
"""

import time
import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, Optional
from collections import defaultdict

import httpx

logger = logging.getLogger("BugBot.SessionManager")


class KillSwitchTriggered(Exception):
    """Excepción lanzada cuando se alcanza el límite diario de peticiones."""
    pass


class SessionManager:
    """
    Gestor de sesiones centralizado para BugBot.
    
    Todas las peticiones HTTP del bot DEBEN pasar por este gestor
    para garantizar el cumplimiento del rate limiting y la
    identificación H1.
    """

    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(
        self,
        daily_limit: int = 10000,
        kill_switch_at: int = 9500,
        per_endpoint_rps: int = 100,
        research_header_name: str = "X-HackerOne-Research",
        research_header_value: str = "[INSERTAR_USERNAME_AQUI]",
        custom_headers: Optional[Dict[str, str]] = None,
    ):
        if self._initialized:
            return
        self._initialized = True

        # --- Configuración de Límites ---
        self.daily_limit = daily_limit
        self.kill_switch_at = kill_switch_at
        self.per_endpoint_rps = per_endpoint_rps

        # --- Contadores Globales ---
        self._request_count = 0
        self._day_start = self._get_today_key()
        self._lock = asyncio.Lock()

        # --- Rate Limiting por Endpoint ---
        self._endpoint_timestamps: Dict[str, list] = defaultdict(list)
        self._endpoint_lock = asyncio.Lock()

        # --- Headers Obligatorios ---
        self._base_headers = {
            research_header_name: research_header_value,
            "X-Bug-Bounty": "True",
        }
        if custom_headers:
            self._base_headers.update(custom_headers)

        # --- Estado del Kill Switch ---
        self._killed = False

        logger.info(
            f"[⚡ SESSION] Inicializado | Límite diario: {daily_limit} | "
            f"Kill Switch: {kill_switch_at} | RPS/endpoint: {per_endpoint_rps}"
        )

    # ------------------------------------------------------------------
    # Utilidades internas
    # ------------------------------------------------------------------
    @staticmethod
    def _get_today_key() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def _reset_if_new_day(self):
        """Reinicia contadores si ha cambiado el día UTC."""
        today = self._get_today_key()
        if today != self._day_start:
            logger.info(
                f"[⚡ SESSION] Nuevo día detectado ({today}). "
                f"Reiniciando contadores (ayer: {self._request_count} peticiones)."
            )
            self._request_count = 0
            self._day_start = today
            self._killed = False
            self._endpoint_timestamps.clear()

    def _extract_endpoint_key(self, url: str) -> str:
        """Extrae una clave única para el endpoint (scheme + host + path)."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    # ------------------------------------------------------------------
    # Control de tráfico
    # ------------------------------------------------------------------
    async def _check_kill_switch(self):
        """Verifica el estado del kill switch antes de cada petición."""
        async with self._lock:
            self._reset_if_new_day()

            if self._killed:
                raise KillSwitchTriggered(
                    f"[🛑 KILL SWITCH] Ejecución detenida. "
                    f"Se alcanzaron {self._request_count}/{self.daily_limit} peticiones hoy."
                )

            if self._request_count >= self.kill_switch_at:
                self._killed = True
                remaining = self.daily_limit - self._request_count
                logger.critical(
                    f"[🛑 KILL SWITCH ACTIVADO] {self._request_count} peticiones realizadas. "
                    f"Quedan {remaining} de margen manual. Deteniendo ejecución automática."
                )
                print(
                    f"\n\033[91m[🛑 KILL SWITCH] Límite alcanzado: "
                    f"{self._request_count}/{self.daily_limit}. "
                    f"Quedan {remaining} para uso manual.\033[0m\n"
                )
                raise KillSwitchTriggered(
                    f"Kill switch activado a {self._request_count} peticiones."
                )

            self._request_count += 1

    async def _enforce_endpoint_rate(self, endpoint_key: str):
        """Aplica rate limiting por endpoint (máx N peticiones/segundo)."""
        async with self._endpoint_lock:
            now = time.monotonic()
            timestamps = self._endpoint_timestamps[endpoint_key]

            # Limpiar timestamps más antiguos de 1 segundo
            self._endpoint_timestamps[endpoint_key] = [
                ts for ts in timestamps if now - ts < 1.0
            ]
            timestamps = self._endpoint_timestamps[endpoint_key]

            if len(timestamps) >= self.per_endpoint_rps:
                # Esperar hasta que el slot más antiguo expire
                wait_time = 1.0 - (now - timestamps[0])
                if wait_time > 0:
                    logger.debug(
                        f"[⚡ SESSION] Rate limit por endpoint: "
                        f"esperando {wait_time:.2f}s para {endpoint_key}"
                    )
                    await asyncio.sleep(wait_time)

            self._endpoint_timestamps[endpoint_key].append(time.monotonic())

    # ------------------------------------------------------------------
    # API Pública - Peticiones HTTP
    # ------------------------------------------------------------------
    def _merge_headers(self, extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Combina headers base (H1 research) con headers adicionales."""
        merged = dict(self._base_headers)
        if extra_headers:
            merged.update(extra_headers)
        return merged

    async def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 15.0,
        follow_redirects: bool = True,
        **kwargs,
    ) -> httpx.Response:
        """GET request con inyección de headers H1 y control de rate."""
        await self._check_kill_switch()
        endpoint = self._extract_endpoint_key(url)
        await self._enforce_endpoint_rate(endpoint)

        async with httpx.AsyncClient(
            headers=self._merge_headers(headers),
            timeout=timeout,
            follow_redirects=follow_redirects,
            verify=False,
        ) as client:
            response = await client.get(url, **kwargs)

        self._log_request("GET", url, response.status_code)
        return response

    async def post(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        json: Optional[dict] = None,
        data: Optional[dict] = None,
        timeout: float = 15.0,
        **kwargs,
    ) -> httpx.Response:
        """POST request con inyección de headers H1 y control de rate."""
        await self._check_kill_switch()
        endpoint = self._extract_endpoint_key(url)
        await self._enforce_endpoint_rate(endpoint)

        async with httpx.AsyncClient(
            headers=self._merge_headers(headers),
            timeout=timeout,
            verify=False,
        ) as client:
            response = await client.post(url, json=json, data=data, **kwargs)

        self._log_request("POST", url, response.status_code)
        return response

    def _log_request(self, method: str, url: str, status: int):
        """Log interno de cada petición con contador visible."""
        level = logging.WARNING if status in (429, 503) else logging.DEBUG
        logger.log(
            level,
            f"[⚡ SESSION] [{self._request_count}/{self.kill_switch_at}] "
            f"{method} {url} -> {status}",
        )

    # ------------------------------------------------------------------
    # Información y Estado
    # ------------------------------------------------------------------
    @property
    def requests_remaining(self) -> int:
        """Peticiones restantes antes del kill switch."""
        self._reset_if_new_day()
        return max(0, self.kill_switch_at - self._request_count)

    @property
    def requests_today(self) -> int:
        """Número total de peticiones realizadas hoy."""
        self._reset_if_new_day()
        return self._request_count

    @property
    def is_killed(self) -> bool:
        """Devuelve True si el kill switch está activo."""
        return self._killed

    def get_status_report(self) -> str:
        """Genera un informe legible del estado actual de la sesión."""
        self._reset_if_new_day()
        return (
            f"📊 Estado de Sesión BugBot\n"
            f"   Fecha UTC: {self._day_start}\n"
            f"   Peticiones hoy: {self._request_count}\n"
            f"   Kill Switch en: {self.kill_switch_at}\n"
            f"   Límite diario: {self.daily_limit}\n"
            f"   Restantes (auto): {self.requests_remaining}\n"
            f"   Kill Switch activo: {'🛑 SÍ' if self._killed else '✅ NO'}"
        )

    def reset(self):
        """Reset manual completo (usar con precaución)."""
        self._request_count = 0
        self._killed = False
        self._day_start = self._get_today_key()
        self._endpoint_timestamps.clear()
        logger.info("[⚡ SESSION] Reset manual completado.")


# ------------------------------------------------------------------
# Ejemplo de uso independiente
# ------------------------------------------------------------------
if __name__ == "__main__":
    async def demo():
        sm = SessionManager(
            daily_limit=10000,
            kill_switch_at=9500,
            per_endpoint_rps=100,
            research_header_value="mi_usuario_h1",
        )
        print(sm.get_status_report())

        # Simular peticiones
        try:
            resp = await sm.get("https://httpbin.org/get")
            print(f"Status: {resp.status_code}")
            print(f"Headers enviados: {resp.request.headers}")
            print(sm.get_status_report())
        except KillSwitchTriggered as e:
            print(f"Kill switch: {e}")

    asyncio.run(demo())
