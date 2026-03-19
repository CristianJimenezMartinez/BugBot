import math
import re
from typing import List, Dict

class EntropyHunter:
    """Motor atómico para detección de secretos por entropía matemática."""
    
    @staticmethod
    def calculate_shannon(data: str) -> float:
        """Calcula la entropía de Shannon."""
        if not data: return 0
        entropy = 0
        for x in set(data):
            p_x = float(data.count(x)) / len(data)
            entropy += - p_x * math.log(p_x, 2)
        return entropy

    def detect_secrets(self, text: str, min_length: int = 20, max_length: int = 256) -> List[Dict]:
        """Escanea bloques de texto buscando alta aleatoriedad."""
        found = []
        words = re.findall(r'\b[A-Za-z0-9+/=_%-]{' + str(min_length) + r',' + str(max_length) + r'}\b', text)
        
        for word in set(words):
            e = self.calculate_shannon(word)
            
            # Umbral de seguridad Bug Bounty
            if e > 5.2:
                # Filtros de ruido
                if re.fullmatch(r'[A-Fa-f0-9\-]+', word) and e < 5.8: continue
                if re.fullmatch(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', word.lower()): continue
                
                tipo = "High Entropy String"
                if word.startswith("eyJ"): tipo = "JWT Token"
                elif word.startswith("AKIA"): tipo = "AWS Access Key"
                
                # Capturar contexto para evidencia
                start = max(0, text.find(word) - 20)
                end = min(len(text), text.find(word) + len(word) + 20)
                context = text[start:end].replace("\n", " ")
                evidence = f"Valor: `{word}` | Contexto: `...{context}...`"

                found.append({
                    "match": word[:6] + "..." + word[-4:],
                    "valor_original": word, # Para uso interno del motor
                    "entropia": round(e, 2),
                    "tipo": tipo,
                    "evidence": {tipo: [evidence]}
                })
        return found
