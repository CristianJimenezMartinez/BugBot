import logging
from typing import List, Dict

logger = logging.getLogger("BugBot.Auth.Fingerprint")

class SessionFingerprinter:
    """Motor atómico para extracción de huellas digitales de identidad."""
    
    @staticmethod
    def extract(session_data: dict) -> List[str]:
        """Extrae strings sensibles de los tokens de sesión."""
        fingerprints = []
        # Rebuscamos en cabeceras comunes
        for k, v in session_data.items():
            k_low = k.lower()
            if any(kw in k_low for kw in ['auth', 'session', 'cookie', 'user', 'email']):
                # TODO: Añadir decoder JWT si el string parece ser un token base64
                pass
        return fingerprints

    @staticmethod
    def check_leak(content: str, fingerprints: List[str]) -> bool:
        """Verifica si alguna huella digital del usuario A aparece en la respuesta B."""
        if not fingerprints: return False
        return any(fp in content for fp in fingerprints if len(fp) > 3)
