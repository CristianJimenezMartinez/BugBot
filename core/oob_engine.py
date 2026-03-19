import asyncio
import aiohttp
import json
import uuid
import logging
from typing import Dict, List, Optional
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from base64 import b64encode, b64decode
from core.config import Config

logger = Config.setup_logger("BugBot.OOBEngine", "bugbot_scanner.log")

class OOBEngine:
    """
    Motor Out-Of-Band (Fase 8)
    Conecta con servidores públicos de Interactsh para crear trampas OOB (Out-Of-Band).
    Genera URLs únicas (ej: `uuid.interactsh.com`) para interceptar SSRFs críticos y Command Injections ciegos.
    """
    
    SERVERS = [
        "https://oast.fun",
        "https://oast.live",
        "https://oast.me",
        "https://interactsh.com",
        "https://oast.site",
        "https://oast.online",
        "https://oast.pro"
    ]
    
    def __init__(self):
        self._keys_generated = False
        self.session_id = str(uuid.uuid4())
        self.correlation_id = str(uuid.uuid4()).replace("-", "")[:20] # Interactsh requiere 20 chars
        self.public_key = ""
        self.private_key = None
        self.active_payloads = {} # Diccionario: { "payload_url": {"target": "http://..", "param": "url"} }
        self.findings = []
        self.current_server = None
        
    def _generate_rsa_keys(self):
        """Interactsh requiere la clave pública RSA en formato PEM codificada en Base64."""
        import base64
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = self.private_key.public_key()
        
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # EL SECRETO: El servidor espera Base64 de la cadena PEM completa
        self.public_key = base64.b64encode(pem).decode("utf-8")
        self._keys_generated = True

    async def register(self) -> Optional[str]:
        """Registra un nuevo canal ciego probando múltiples servidores de respaldo."""
        if not self._keys_generated:
            self._generate_rsa_keys()
            
        payload = {
            "public-key": self.public_key,
            "secret-key": self.session_id,
            "correlation-id": self.correlation_id
        }
        
        headers = {
            "Content-Type": "application/json",
            "User-Agent": Config.get_random_user_agent()
        }
        
        connector = Config.get_connector()
        async with aiohttp.ClientSession(connector=connector) as session:
            for server in self.SERVERS:
                try:
                    logger.debug(f"[OOB] Intentando registro en: {server}")
                    async with session.post(f"{server}/register", json=payload, headers=headers, timeout=10) as resp:
                        if resp.status == 200:
                            self.current_server = server
                            # Extraer el dominio base (ej. oast.fun) de la URL
                            base_oast = server.replace("https://", "")
                            self.full_oast_host = f"{self.correlation_id}.{base_oast}"
                            logger.info(f"[🦇 OOB] Canal Ciego Establecido en: {self.full_oast_host}")
                            return self.full_oast_host
                        else:
                            error_text = await resp.text()
                            logger.debug(f"[OOB] Servidor {server} rechazó el registro (Status {resp.status}): {error_text}")
                except Exception as e:
                    logger.debug(f"[OOB] Error de conexión con {server}: {e}")
                    continue
            
        logger.error("[OOB Engine] No se pudo establecer conexión con ningún servidor OAST público.")
        return None

    def generate_payload(self, target_url: str, param_name: str = "Headers") -> str:
        """Genera una URL ciega y la asocia al objetivo para trazabilidad posterior."""
        if not hasattr(self, 'full_oast_host'):
            return "interact_not_ready"
            
        # Creamos un identificador corto (8 chars) para saber qué ataque y en qué web originó el ping
        attack_id = str(uuid.uuid4())[:8]
        payload = f"http://{attack_id}.{self.full_oast_host}"
        
        self.active_payloads[attack_id] = {
            "target": target_url,
            "param": param_name,
            "timestamp": asyncio.get_running_loop().time()
        }
        
        return payload

    async def poll_interactions(self, duration_minutes: int = 15):
        """Se queda escuchando en segundo plano (Polling persistente para SSRF asíncrono)."""
        if not hasattr(self, 'full_oast_host'):
            return
            
        logger.info(f"[🦇 OOB] Escuchando pingbacks ciegos (Modo Persistente: {duration_minutes} min)...")
        
        end_time = asyncio.get_running_loop().time() + (duration_minutes * 60)
        
        headers = {
            "Authorization": self.session_id,
            "User-Agent": Config.get_random_user_agent()
        }
        
        connector = Config.get_connector()
        async with aiohttp.ClientSession(connector=connector) as session:
            while asyncio.get_running_loop().time() < end_time:
                try:
                    url = f"{self.current_server}/poll?id={self.correlation_id}&secret={self.session_id}"
                    async with session.get(url, headers=headers, timeout=10) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if data and "data" in data:
                                # Las interacciones vienen cifradas AES
                                aes_key_enc = data.get("aes_key")
                                for interaction_enc in data["data"]:
                                    self._process_interaction(interaction_enc, aes_key_enc)
                except Exception:
                    pass
                    
                await asyncio.sleep(20) # Polling cada 20 segundos para no saturar la API
        
        logger.info("[🦇 OOB] Monitorización Out-Of-Band finalizada.")

    def _process_interaction(self, encrypted_data: str, encrypted_aes_key: str):
        """
        Descifrado de Grado Élite (RSA-OAEP + AES-CFB).
        Permite leer cabeceras internas y fugas de datos en el cuerpo de la petición OOB.
        """
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding
            import base64

            # 1. Desencriptar la clave AES usando nuestra clave privada RSA
            if not self.private_key or not encrypted_aes_key:
                return

            decrypted_aes_key = self.private_key.decrypt(
                base64.b64decode(encrypted_aes_key),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # 2. Desencriptar el contenido de la interacción usando AES-CFB
            raw_enc = base64.b64decode(encrypted_data)
            iv = raw_enc[:16] # Los primeros 16 bytes son el IV
            ciphertext = raw_enc[16:]
            
            cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.CFB(iv))
            decryptor = cipher.decryptor()
            decrypted_json = decryptor.update(ciphertext) + decryptor.finalize()
            
            interaction = json.loads(decrypted_json.decode('utf-8', errors='ignore'))
            
            # 3. Procesar el hallazgo
            full_id = interaction.get("full-id", "")
            protocol = interaction.get("protocol", "Unknown")
            remote_ip = interaction.get("remote-address", "Unknown IP")
            
            attack_id = full_id.split(".")[0]
            
            if attack_id in self.active_payloads:
                context = self.active_payloads[attack_id]
                logger.warning(f"\n[🚨] VULNERABILIDAD CIEGA CRÍTICA CONFIRMADA (OOB) [{protocol}]")
                logger.warning(f"  -> IP Atacante/Servidor: {remote_ip}")
                logger.warning(f"  -> Inyección Original: {context['target']} (Parámetro: {context['param']})")
                
                # Fuga de Datos (Headers/Body)
                raw_request = interaction.get("raw-request", "")
                if raw_request:
                    logger.info(f"  [🔍] Datos Extraídos (Raw Request):\n{raw_request[:500]}...")

                self.findings.append({
                    "tipo": "BLIND_SSRF_OOB",
                    "impacto": "CRITICAL",
                    "url": context['target'],
                    "param": context['param'],
                    "protocolo": protocol,
                    "raw_data": raw_request,
                    "ip_fuga": remote_ip
                })
        except Exception as e:
            logger.debug(f"[OOB Decrypt Error] {e}")

# Testing unitario
if __name__ == "__main__":
    async def test():
        oob = OOBEngine()
        oast = await oob.register()
        print("URL generada:", oob.generate_payload("https://playtika.com/api", "avatar_url"))
        print("Poll activo por 30 sec (lanza un ping a la URL oast para probar)...")
        await oob.poll_interactions(duration_minutes=0.5)
        print("Findings:", oob.findings)
    asyncio.run(test())
