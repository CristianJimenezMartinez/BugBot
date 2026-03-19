class PoCGenerator:
    """Motor atómico para generación de comandos cURL reproducibles."""
    
    @staticmethod
    def generate_curl(url: str, method: str = "GET", headers: dict = None, payload: str = None) -> str:
        """Convierte una petición en un comando cURL limpio."""
        hdrs = headers or {}
        curl_cmd = f"curl -X {method} '{url}' \\\n"
        
        interesting_headers = [
            'x-forwarded-for', 'x-custom-ip-authorization', 'x-original-url', 
            'x-rewrite-url', 'authorization', 'cookie', 'content-type'
        ]
        
        for k, v in hdrs.items():
            if k.lower() in interesting_headers:
                curl_cmd += f"  -H '{k}: {v}' \\\n"
                
        if payload and method.upper() in ['POST', 'PUT', 'PATCH']:
            curl_cmd += f"  -d '{payload}'"
            
        return curl_cmd.rstrip(' \\\n')
